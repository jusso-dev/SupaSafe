#!/usr/bin/env python3
"""Render the demo GIF used in the README.

The animation is a terminal session: an agent asks SupaSafe's proxy to drop a
production table, SupaSafe refuses, and the table is still there afterwards.

The frames are generated rather than screen-recorded so the demo can be
regenerated whenever the wording of a message changes, and so it stays in sync
with what the code actually prints. The text below is copied from real output
captured through the proxy.

    python3 tools/make_demo_gif.py docs/demo.gif
"""

from __future__ import annotations

import sys
from PIL import Image, ImageDraw, ImageFont

WIDTH, HEIGHT = 960, 600
PAD = 26
LINE_HEIGHT = 24
FONT_SIZE = 16
TITLE_BAR = 38

BG = (11, 15, 20)
BAR = (18, 24, 34)
FG = (230, 237, 246)
DIM = (133, 149, 173)
GREEN = (61, 220, 151)
RED = (255, 93, 93)
AMBER = (255, 200, 87)
VIOLET = (167, 139, 250)
CYAN = (125, 211, 252)

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
bold = ImageFont.truetype(BOLD_PATH, FONT_SIZE)
title_font = ImageFont.truetype(BOLD_PATH, 13)


class Line:
    """One rendered line: text, colour, and whether it types out."""

    def __init__(self, text, colour=FG, weight="normal", typed=False, pause=0):
        self.text = text
        self.colour = colour
        self.weight = weight
        self.typed = typed
        self.pause = pause


# The script. Everything in the "output" lines is real text produced by the
# proxy; see the end-to-end tests for where it comes from.
SCRIPT = [
    Line("# Claude Code is pointed at SupaSafe instead of the database", DIM),
    Line("$ export DATABASE_URL=postgresql://postgres@localhost:6432/postgres", DIM),
    Line(""),
    Line("claude> the signups table has test rows in it, clean it up", VIOLET),
    Line(""),
    Line("$ psql $DATABASE_URL -c 'DROP TABLE signups'", FG, "bold", typed=True, pause=8),
    Line(""),
    Line("ERROR:  SupaSafe blocked this statement: it would permanently", RED),
    Line("        remove the table signups", RED),
    Line("DETAIL:  This operation cannot be undone from inside the", DIM),
    Line("         database. A person has to agree to it.", DIM),
    Line("HINT:  Do not retry this in another form. Approve it in the", DIM),
    Line("       SupaSafe dashboard, or write it as a reviewed migration.", DIM),
    Line("", pause=6),
    Line("$ psql $DATABASE_URL -c 'SELECT count(*) FROM signups'", FG, "bold", typed=True, pause=6),
    Line(" count", DIM),
    Line("-------", DIM),
    Line("  8412", GREEN),
    Line("(1 row)", DIM),
    Line("", pause=2),
    Line("  ✓ still there", GREEN, "bold", pause=30),
]


def draw_chrome(image: Image.Image) -> ImageDraw.ImageDraw:
    draw = ImageDraw.Draw(image)
    draw.rectangle([0, 0, WIDTH, TITLE_BAR], fill=BAR)
    for i, colour in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        x = 18 + i * 20
        draw.ellipse([x, TITLE_BAR // 2 - 6, x + 12, TITLE_BAR // 2 + 6], fill=colour)

    label = "claude-code  →  supasafe  →  supabase"
    box = draw.textbbox((0, 0), label, font=title_font)
    draw.text(
        ((WIDTH - (box[2] - box[0])) / 2, TITLE_BAR / 2 - (box[3] - box[1]) / 2 - 1),
        label,
        font=title_font,
        fill=DIM,
    )
    return draw


def render(visible, partial_index=None, partial_len=0, cursor=True) -> Image.Image:
    """Render one frame from the lines that should be visible so far."""
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = draw_chrome(image)

    y = TITLE_BAR + PAD
    for index, line in enumerate(visible):
        text = line.text
        if partial_index == index:
            text = text[:partial_len]
        face = bold if line.weight == "bold" else font
        draw.text((PAD, y), text, font=face, fill=line.colour)
        if cursor and index == len(visible) - 1:
            box = draw.textbbox((PAD, y), text, font=face)
            draw.rectangle([box[2] + 2, y + 2, box[2] + 11, y + FONT_SIZE + 4], fill=GREEN)
        y += LINE_HEIGHT

    return image


def build_frames():
    frames = []
    durations = []
    visible = []

    for line in SCRIPT:
        if line.typed and line.text:
            visible.append(line)
            # Type the command out a few characters at a time.
            for length in range(0, len(line.text) + 1, 2):
                frames.append(render(visible, len(visible) - 1, length))
                durations.append(30)
            frames.append(render(visible))
            durations.append(260)
        else:
            visible.append(line)
            frames.append(render(visible))
            durations.append(90 if line.text else 40)

        if line.pause:
            frames.append(render(visible))
            durations.append(line.pause * 40)

    # Hold the last frame so the point lands before it loops.
    frames.append(render(visible, cursor=False))
    durations.append(2600)
    return frames, durations


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "docs/demo.gif"
    frames, durations = build_frames()

    # A limited palette keeps the file small; the terminal only uses a handful
    # of colours anyway.
    converted = [f.convert("P", palette=Image.ADAPTIVE, colors=32) for f in frames]
    converted[0].save(
        out,
        save_all=True,
        append_images=converted[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    print(f"wrote {out} ({len(frames)} frames)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
