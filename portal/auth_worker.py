#!/usr/bin/env python3
"""Keep scrypt work memory out of the long-lived controller. Secrets use stdin."""
import hashlib
import hmac
import json
import secrets
import sys


def password_hash(password, salt=None):
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise ValueError('Administrator password must contain 12-128 characters')
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return {'salt':salt, 'hash':digest}


def password_matches(password, record):
    try:
        return hmac.compare_digest(password_hash(password, record['salt'])['hash'], record['hash'])
    except (ValueError, TypeError):
        return False


def main():
    request=json.loads(sys.stdin.buffer.read(4097))
    if request['action']=='hash':
        result={'record':password_hash(request['password'])}
    elif request['action']=='verify':
        result={'valid':password_matches(request['password'],request['record'])}
    else:
        raise ValueError('Unknown action')
    print(json.dumps(result))


if __name__=='__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError):
        sys.exit(1)
