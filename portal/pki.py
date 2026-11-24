"""Device-local CA lifecycle. This module is used only by privileged tooling."""
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import uuid
import fcntl
from storage import write

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PEM = serialization.Encoding.PEM


def key_pem(key):
    return key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def metadata(cert):
    fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
    return {'name': cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            'fingerprint': ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)),
            'expires': cert.not_valid_after_utc.isoformat(), 'serial': str(cert.serial_number)}


def validate_ca(directory):
    combined = (directory / 'mitmproxy-ca.pem').read_bytes()
    key = serialization.load_pem_private_key(combined, password=None)
    cert = x509.load_pem_x509_certificate(combined)
    if key.public_key().public_numbers() != cert.public_key().public_numbers():
        raise ValueError('CA certificate and private key do not match')
    if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError('Stored certificate is not a CA')
    if not cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
        raise ValueError('CA lacks signing permission')
    cert.verify_directly_issued_by(cert)
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError('CA is not currently valid; check the clock or explicitly rotate it')
    return key, cert


def make_leaf(directory, gateway):
    ca_key, ca = validate_ca(directory)
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'NetBridge local portal')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(min(now + timedelta(days=365), ca.not_valid_after_utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(gateway))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    write(directory / 'portal-key.pem', key_pem(key))
    write(directory / 'portal-cert.pem', cert.public_bytes(PEM))


def provision(root, gateway, rotate=False):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    current = root / 'current'
    if current.is_symlink() and not current.exists():
        raise ValueError('CA link is broken; refusing automatic replacement')
    if current.exists() and not rotate:
        validate_ca(current)
        return metadata(x509.load_pem_x509_certificate((current / 'mitmproxy-ca-cert.pem').read_bytes()))
    if not current.exists() and any(root.iterdir()):
        raise ValueError('CA directory contains incomplete material; explicit recovery required')
    directory = root / uuid.uuid4().hex
    directory.mkdir(mode=0o700)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'NetBridge CA ' + directory.name[:8])])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=7305))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    write(directory / 'mitmproxy-ca.pem', key_pem(key) + cert.public_bytes(PEM))
    write(directory / 'mitmproxy-ca-cert.pem', cert.public_bytes(PEM))
    write(directory / 'mitmproxy-ca-cert.cer', cert.public_bytes(PEM))
    make_leaf(directory, gateway)
    validate_ca(directory)
    temporary = root / 'next'
    temporary.symlink_to(directory.name)
    os.replace(temporary, current)
    # Keep at most one previous root-only generation for deliberate recovery.
    generations = sorted([p for p in root.iterdir() if re.fullmatch(r'[0-9a-f]{32}', p.name)
                          and p.is_dir() and not p.is_symlink()], key=lambda p: p.stat().st_mtime, reverse=True)
    for old in generations[2:]:
        if old.parent.resolve() == root.resolve() and old != current.resolve():
            shutil.rmtree(old)
    return metadata(cert)


def publish(root, public, tls, gateway, portal_gid, proxy_dir=None, proxy_gid=None):
    current = Path(root) / 'current'
    _, ca = validate_ca(current)
    leaf_path = current / 'portal-cert.pem'
    renew = not leaf_path.exists()
    if not renew:
        leaf = x509.load_pem_x509_certificate(leaf_path.read_bytes())
        renew = leaf.not_valid_after_utc < datetime.now(timezone.utc) + timedelta(days=30)
    if renew:
        make_leaf(current, gateway)
    public, tls = Path(public), Path(tls)
    public.mkdir(parents=True, exist_ok=True, mode=0o755)
    tls.mkdir(parents=True, exist_ok=True, mode=0o750)
    os.chown(tls, 0, portal_gid)
    write(public / 'netbridge-ca.crt', ca.public_bytes(PEM), 0o644)
    write(public / 'ca.json', json.dumps(metadata(ca)), 0o644)
    for filename in ('portal-cert.pem', 'portal-key.pem'):
        destination = tls / filename
        write(destination, (current / filename).read_bytes(), 0o640)
        os.chown(destination, 0, portal_gid)
    if proxy_dir is not None and proxy_gid is not None:
        proxy_dir = Path(proxy_dir)
        proxy_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        os.chmod(proxy_dir, 0o750)
        os.chown(proxy_dir, 0, proxy_gid)
        for filename in ('mitmproxy-ca.pem', 'mitmproxy-ca-cert.pem'):
            destination = proxy_dir / filename
            write(destination, (current / filename).read_bytes(), 0o640)
            os.chown(destination, 0, proxy_gid)
    return renew


def refresh(root, public, tls, gateway, portal_gid, rotate=False, proxy_dir=None, proxy_gid=None):
    # Serialize timer renewal, installation and browser-requested CA rotation.
    lock_path = Path(root).parent / 'ca-lifecycle.lock'
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        provision(root, gateway, rotate)
        return publish(root, public, tls, gateway, portal_gid, proxy_dir=proxy_dir, proxy_gid=proxy_gid)
