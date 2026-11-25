#!/usr/bin/python3
"""One-shot RGB565 screen renderer. Credentials only travel through pipes."""
import json
from pathlib import Path
import sys
from PIL import Image, ImageDraw, ImageFont

FONT_CANDIDATES = {
    True: (
        '/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Bold.ttf',
        '/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf',
        '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
        'C:/Windows/Fonts/consolab.ttf',
        'C:/Windows/Fonts/arialbd.ttf',
    ),
    False: (
        '/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf',
        '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
        '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
        'C:/Windows/Fonts/consola.ttf',
        'C:/Windows/Fonts/arial.ttf',
    ),
}

BG = '#0B0D10'
SURFACE = '#11151A'
RAISED = '#161B22'
BORDER = '#21262D'
TEXT = '#E6EDF3'
TEXT_SEC = '#B6C2CF'
TEXT_MUTED = '#8B98A5'
ACCENT_RED = '#C44B4B'
LIVE_BG = '#18271E'
LIVE_FG = '#9CC2A7'
LIVE_BORDER = '#385441'
WARN_BG = '#2D1619'
WARN_FG = '#E5A0A0'
WARN_BORDER = '#6E2D33'


def _font_path(bold=False):
    for candidate in FONT_CANDIDATES[bold]:
        if Path(candidate).is_file():
            return candidate
    return None


def _load_font(size, bold=False):
    path = _font_path(bold)
    if path:
        return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _load_logo(size=44):
    for candidate in (
        Path('/usr/local/lib/netbridge/adversaryicu-logo.png'),
        Path(__file__).resolve().parents[1] / 'assets/adversaryicu-logo.png',
    ):
        if candidate.is_file():
            try:
                return Image.open(candidate).convert('RGBA').resize((size, size), Image.Resampling.LANCZOS)
            except OSError:
                return None
    return None


def render(data):
    image = Image.new('RGB', (320, 170), BG)
    draw = ImageDraw.Draw(image)

    def text(x, y, value, size=13, color=TEXT, width=290, bold=False):
        cur = size
        font = _load_font(cur, bold=bold)
        while cur > 9 and draw.textlength(value, font=font) > width:
            cur -= 1
            font = _load_font(cur, bold=bold)
        draw.text((x, y), value, font=font, fill=color)

    def label_row(y, label, value, value_color=TEXT, value_bold=False, size=13, value_width=224):
        text(16, y, label, 11, TEXT_MUTED, 62, bold=True)
        text(78, y - 1, value, size, value_color, value_width, bold=value_bold)

    # Header bar
    draw.rectangle((0, 0, 319, 28), fill=RAISED)
    draw.rectangle((0, 28, 319, 28), fill=BORDER)
    draw.rectangle((0, 0, 3, 28), fill=ACCENT_RED)
    text(11, 6, 'NETBRIDGE // TAP', 14, TEXT, 200, bold=True)

    is_msg = 'message' in data
    is_country = data.get('prompt') == 'country'
    msg_lower = str(data.get('message', '')).lower()
    if is_country:
        badge, b_bg, b_fg, b_bd = 'SETUP', '#19222D', '#9BB4CE', '#2E4054'
    elif is_msg:
        if 'unable' in msg_lower or 'fail' in msg_lower or 'error' in msg_lower:
            badge, b_bg, b_fg, b_bd = 'ERR', WARN_BG, WARN_FG, WARN_BORDER
        elif 'stop' in msg_lower:
            badge, b_bg, b_fg, b_bd = 'STOP', WARN_BG, WARN_FG, WARN_BORDER
        else:
            badge, b_bg, b_fg, b_bd = 'BOOT', '#19222D', '#9BB4CE', '#2E4054'
    else:
        badge, b_bg, b_fg, b_bd = 'LIVE', LIVE_BG, LIVE_FG, LIVE_BORDER

    badge_w = int(draw.textlength(badge, font=_load_font(11, bold=True))) + 14
    bx0 = 311 - badge_w
    draw.rectangle((bx0, 5, 311, 23), fill=b_bg, outline=b_bd)
    text(bx0 + 7, 7, badge, 11, b_fg, badge_w, bold=True)

    # Main content panel
    draw.rectangle((8, 34, 311, 141), fill=SURFACE, outline=BORDER)

    if is_country:
        code = str(data.get('code', '') or '').upper()[:2]
        text(18, 43, 'Set Wi-Fi Country Code', 14, TEXT, 284, bold=True)
        text(18, 63, 'Type 2-letter ISO code (e.g. US, GB, DE)', 11, TEXT_MUTED, 284)
        for idx, bx in enumerate((110, 166)):
            ch = code[idx] if idx < len(code) else '_'
            active_slot = idx == len(code) or (len(code) == 2 and idx == 1)
            bd = LIVE_BORDER if len(code) == 2 else (ACCENT_RED if active_slot else BORDER)
            fg = LIVE_FG if len(code) == 2 else (TEXT if idx < len(code) else TEXT_MUTED)
            draw.rectangle((bx, 83, bx + 40, 118), fill=RAISED, outline=bd)
            text(bx + 13, 91, ch, 18, fg, 24, bold=True)
        if data.get('error'):
            text(18, 123, data['error'], 11, WARN_FG, 284)
    elif is_msg:
        text(18, 62, data['message'], 15, TEXT, 284, bold=True)
        text(18, 92, data.get('detail', 'Please wait…'), 12, TEXT_MUTED, 284)
    else:
        show_pw = bool(data.get('show_password', False))
        pw_display = data.get('password', '') if show_pw else '•' * min(14, max(8, len(data.get('password', ''))))
        pw_color = LIVE_FG if show_pw else TEXT_SEC

        logo = _load_logo(44)
        val_width = 172 if logo is not None else 224
        label_row(43, 'SSID', data.get('ssid', ''), TEXT, value_bold=True, size=14, value_width=val_width)
        label_row(65, 'PASS', pw_display, pw_color, value_bold=show_pw, size=14, value_width=val_width)
        if logo is not None:
            image.paste(logo, (259, 39), logo)
        draw.line((16, 87, 303, 87), fill=BORDER)
        label_row(95, 'SETUP', data.get('url', 'http://192.168.50.1'), TEXT_SEC, size=13)
        if data.get('pairing'):
            label_row(117, 'PAIR', data['pairing'], ACCENT_RED, value_bold=True, size=13)
        else:
            base = str(data.get('url', 'http://192.168.50.1')).replace('http://', 'https://').rstrip('/')
            label_row(117, 'TAP UI', f'{base}/inspector', TEXT_MUTED, size=12)

    # Footer keybar
    draw.rectangle((0, 146, 319, 169), fill=RAISED)
    draw.rectangle((0, 146, 319, 146), fill=BORDER)
    if is_country:
        text(10, 151, '[A-Z] TYPE   [ENT] SAVE', 11, TEXT_SEC, 190, bold=True)
        text(228, 151, '[ESC] EXIT', 11, ACCENT_RED, 86, bold=True)
    else:
        if not is_msg:
            toggle_label = '[R/5] HIDE PASS' if data.get('show_password', False) else '[R/5] SHOW PASS'
            text(10, 151, toggle_label, 11, TEXT_SEC, 160, bold=True)
        text(204, 151, '[ESC] STOP TAP', 11, ACCENT_RED, 110, bold=True)
    return image


if __name__ == '__main__':
    image = render(json.load(sys.stdin))
    output = bytearray()
    for r, g, b in image.getdata():
        output.extend((((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)).to_bytes(2, 'little'))
    sys.stdout.buffer.write(output)
