#!/usr/bin/python3
"""One-shot RGB565 screen renderer. Credentials only travel through pipes."""
import json
import sys
from PIL import Image, ImageDraw, ImageFont


def render(data):
    image = Image.new('RGB', (320, 170), '#0b1724')
    draw = ImageDraw.Draw(image)
    font_path = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
    def text(x, y, value, size=14, color='#edf5ff', width=300):
        while size > 8:
            font = ImageFont.truetype(font_path, size)
            if draw.textlength(value, font=font) <= width:
                break
            size -= 1
        draw.text((x, y), value, font=font, fill=color)
    draw.rectangle((0, 0, 319, 31), fill='#17465b')
    text(10, 3, 'NetBridge', 21)
    if 'message' in data:
        text(10, 59, data['message'], 16)
        text(10, 92, data.get('detail', 'Please wait'), 14, '#94bdcc')
    else:
        text(10, 37, '1  Join Wi-Fi: ' + data['ssid'], 15)
        text(10, 62, data['password'], 19, '#72e2bc')
        text(10, 89, '2  Open ' + data['url'], 16)
        text(10, 113, 'Install CA, then check trust', 14, '#94bdcc')
        if data.get('pairing'):
            text(10, 134, 'Admin code: ' + data['pairing'], 13)
    text(10, 152, 'ESC: stop hotspot and return', 12, '#94bdcc')
    return image


if __name__ == '__main__':
    image = render(json.load(sys.stdin))
    output = bytearray()
    for r, g, b in image.getdata():
        output.extend((((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)).to_bytes(2, 'little'))
    sys.stdout.buffer.write(output)
