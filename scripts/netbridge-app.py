#!/usr/bin/python3 -I
"""Unprivileged native Cardputer screen; networking belongs to a leased session."""
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import time

ROOT = Path('/usr/local/lib/netbridge')
KEY_LETTERS = {
    16: 'Q', 17: 'W', 18: 'E', 19: 'R', 20: 'T', 21: 'Y', 22: 'U', 23: 'I', 24: 'O', 25: 'P',
    30: 'A', 31: 'S', 32: 'D', 33: 'F', 34: 'G', 35: 'H', 36: 'J', 37: 'K', 38: 'L',
    44: 'Z', 45: 'X', 46: 'C', 47: 'V', 48: 'B', 49: 'N', 50: 'M',
}
running = True


def stop(*_):
    global running
    running = False


def draw(data):
    # Render in a worker so Pillow/font allocations do not remain resident.
    pixels = subprocess.check_output(['/usr/bin/python3', '-I', str(ROOT / 'netbridge-screen.py')],
                                     input=json.dumps(data).encode(), timeout=10)
    if len(pixels) != 320 * 170 * 2:
        raise RuntimeError('Unexpected screen size')
    with open('/dev/fb0', 'r+b', buffering=0) as fb:
        fb.write(pixels)


def main():
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
    if (Path('/sys/class/graphics/fb0/bits_per_pixel').read_text().strip() != '16'
            or Path('/sys/class/graphics/fb0/virtual_size').read_text().strip() != '320,170'):
        raise RuntimeError('This build requires the Cardputer 320x170 RGB565 framebuffer')
    key = os.open('/dev/input/by-path/platform-3f804000.i2c-event', os.O_RDONLY | os.O_NONBLOCK)
    draw({'message': 'Starting Network Tap...', 'detail': 'Bringing up AP and portal'})
    proc = subprocess.Popen(['sudo', '-n', str(ROOT / 'netbridge-session.py')],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        buffer = b''
        ready = False
        prompt_mode = None
        country_code = ''
        session_data = None
        show_password = False
        deadline = time.monotonic() + 120
        heartbeat = 0
        while running and proc.poll() is None:
            readable, _, _ = select.select([key, proc.stdout], [], [], 0.25)
            if key in readable:
                events = os.read(key, 24 * 32)
                for offset in range(0, len(events), 24):
                    _, _, kind, code, value = struct.unpack('llHHi', events[offset:offset + 24])
                    if kind == 1 and value == 1:
                        if code == 1:
                            stop()
                        elif prompt_mode == 'country':
                            if code in KEY_LETTERS and len(country_code) < 2:
                                country_code += KEY_LETTERS[code]
                                draw({'prompt': 'country', 'code': country_code})
                            elif code == 14 and country_code:
                                country_code = country_code[:-1]
                                draw({'prompt': 'country', 'code': country_code})
                            elif code == 28:
                                if len(country_code) == 2 and country_code != '00':
                                    proc.stdin.write((json.dumps({'country': country_code}) + '\n').encode())
                                    proc.stdin.flush()
                                    prompt_mode = None
                                    deadline = time.monotonic() + 120
                                    draw({'message': f'Setting country {country_code}...', 'detail': 'Starting Network Tap'})
                                else:
                                    draw({'prompt': 'country', 'code': country_code, 'error': 'Enter 2 letters (e.g. US, GB, DE)'})
                        elif code in (19, 6) and ready and session_data is not None:
                            show_password = not show_password
                            draw({**session_data, 'show_password': show_password})
            if proc.stdout in readable:
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    break
                buffer += chunk
                if len(buffer) > 8192:
                    raise RuntimeError('Invalid session response')
                while b'\n' in buffer and not ready:
                    line, buffer = buffer.split(b'\n', 1)
                    if not line.strip():
                        continue
                    msg = json.loads(line)
                    if msg.get('prompt') == 'country':
                        prompt_mode = 'country'
                        country_code = ''
                        draw({'prompt': 'country', 'code': ''})
                    else:
                        session_data = msg
                        draw({**session_data, 'show_password': show_password})
                        ready = True
            if ready and time.monotonic() > heartbeat:
                proc.stdin.write(b'alive\n')
                proc.stdin.flush()
                heartbeat = time.monotonic() + 3
            if not ready and prompt_mode is None and time.monotonic() > deadline:
                raise RuntimeError('Startup timed out')
        if running:
            draw({'message': 'Unable to run. See session log.', 'detail': 'Press ESC to return.'})
            while running:
                if select.select([key], [], [], 0.5)[0]:
                    events = os.read(key, 24 * 32)
                    for offset in range(0, len(events), 24):
                        _, _, kind, code, value = struct.unpack('llHHi', events[offset:offset + 24])
                        if kind == 1 and code == 1 and value == 1:
                            stop()
    finally:
        draw({'message': 'Stopping Network Tap...', 'detail': 'Restoring previous Wi-Fi'})
        proc.stdin.close()
        try:
            proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            pass  # The systemd session still owns cleanup.
        os.close(key)


if __name__ == '__main__':
    main()
