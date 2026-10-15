#!/usr/bin/env python3
"""Render the README terminal demonstration.

Requires Pillow: python3 -m pip install Pillow
"""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

WIDTH = 1400
HEIGHT = 720
BACKGROUND = "#151515"
FOREGROUND = "#e4e4e4"
DIM = "#808080"
CYAN = "#5fd7ff"
GREEN = "#5fd787"
YELLOW = "#ffd75f"
RED = "#ff5f5f"
FONT_SIZE = 18
LINE_HEIGHT = 20
LEFT = 46
REPORT_TOP = 100
SPINNER_TICKS = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")

Run = tuple[str, str, bool]
Line = list[Run]


def font_candidates(bold: bool) -> tuple[tuple[str, int], ...]:
    weight = "Bold" if bold else "Regular"
    return (
        ("/System/Library/Fonts/Menlo.ttc", 1 if bold else 0),
        (f"/usr/share/fonts/truetype/dejavu/DejaVuSansMono-{weight}.ttf", 0),
        (f"C:/Windows/Fonts/consola{'b' if bold else ''}.ttf", 0),
    )


def load_font(bold: bool) -> ImageFont.FreeTypeFont:
    for candidate, index in font_candidates(bold):
        path = Path(candidate)
        if path.exists():
            return ImageFont.truetype(path, FONT_SIZE, index=index)
    raise SystemExit("No supported monospace font found; update font_candidates()")


def load_spinner_font() -> ImageFont.FreeTypeFont:
    for candidate in (
        "/System/Library/Fonts/Apple Symbols.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "C:/Windows/Fonts/seguisym.ttf",
    ):
        path = Path(candidate)
        if path.exists():
            return ImageFont.truetype(path, FONT_SIZE)
    return load_font(False)


REGULAR = load_font(False)
BOLD = load_font(True)
SPINNER_FONT = load_spinner_font()


def line(*runs: Run) -> Line:
    return list(runs)


REPORT: list[Line] = [
    line(("✗ ", RED, True), ("Code Buster", CYAN, True), (" — ", FOREGROUND, False), ("3 actionable findings", RED, True)),
    line(),
    line(("  Files       ", DIM, False), ("3002 analyzed", FOREGROUND, False)),
    line(("  Warnings    ", DIM, False), ("2", YELLOW, False)),
    line(("  Info        ", DIM, False), ("1", CYAN, False)),
    line(("  Time        ", DIM, False), ("423ms", FOREGROUND, False)),
    line(("  Cache       ", DIM, False), ("miss", FOREGROUND, False)),
    line(),
    line(("Languages", FOREGROUND, True)),
    line(("  python        3001 files     ", FOREGROUND, False), ("2 findings", CYAN, False)),
    line(("  typescript       1 file      ", FOREGROUND, False), ("1 finding", CYAN, False)),
    line(),
    line(("Findings", FOREGROUND, True)),
    line(),
    line(("  WARN  ", YELLOW, True), ("ai-prompt-injection-instruction", CYAN, True)),
    line(("        src/agent.py:4", DIM, False)),
    line(("        prompt contains an instruction commonly used to override trusted directions", FOREGROUND, False)),
    line(),
    line(("  INFO  ", CYAN, True), ("py-hardcoded-secret", CYAN, True)),
    line(("        src/agent.py:5", DIM, False)),
    line(("        possible hardcoded secret", FOREGROUND, False)),
    line(),
    line(("  WARN  ", YELLOW, True), ("sql-inline-string-concat", CYAN, True)),
    line(("        src/server.ts:8", DIM, False)),
    line(("        inline SQL appears dynamically concatenated or interpolated", FOREGROUND, False)),
    line(),
    line(("  → Review actionable findings: ", DIM, False), ("cb review --verbose", CYAN, True)),
]


def draw_runs(draw: ImageDraw.ImageDraw, x: int, y: int, runs: Line) -> None:
    for text, color, bold in runs:
        selected_font = BOLD if bold else REGULAR
        draw.text((x, y), text, fill=color, font=selected_font)
        x += round(draw.textlength(text, font=selected_font))


def base_frame(command: str, cursor: bool) -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT), BACKGROUND)
    draw = ImageDraw.Draw(image)
    for x, color in ((30, RED), (46, YELLOW), (62, GREEN)):
        draw.ellipse((x - 5, 25, x + 5, 35), fill=color)
    draw.text((LEFT, 58), "❯", fill=FOREGROUND, font=BOLD)
    command_x = LEFT + round(draw.textlength("❯ ", font=BOLD))
    draw.text((command_x, 58), command, fill=FOREGROUND, font=REGULAR)
    if cursor:
        cursor_x = command_x + round(draw.textlength(command, font=REGULAR)) + 2
        draw.rectangle((cursor_x, 59, cursor_x + 9, 77), fill=FOREGROUND)
    return image


def spinner_frame(tick: str, message: str) -> Image.Image:
    image = base_frame("cb", False)
    draw = ImageDraw.Draw(image)
    draw.text((LEFT, REPORT_TOP), tick, fill=CYAN, font=SPINNER_FONT)
    tick_width = round(draw.textlength(f"{tick} ", font=SPINNER_FONT))
    draw.text((LEFT + tick_width, REPORT_TOP), message, fill=FOREGROUND, font=REGULAR)
    return image


def report_frame() -> Image.Image:
    image = base_frame("cb", False)
    draw = ImageDraw.Draw(image)
    for index, runs in enumerate(REPORT):
        draw_runs(draw, LEFT, REPORT_TOP + index * LINE_HEIGHT, runs)
    prompt_y = REPORT_TOP + len(REPORT) * LINE_HEIGHT + 8
    draw.text((LEFT, prompt_y), "❯", fill=FOREGROUND, font=BOLD)
    draw.rectangle((LEFT + 25, prompt_y + 1, LEFT + 34, prompt_y + 19), fill=FOREGROUND)
    return image


def render(output: Path) -> None:
    frames: list[Image.Image] = []
    durations: list[int] = []

    def add(frame: Image.Image, duration: int) -> None:
        frames.append(frame)
        durations.append(duration)

    add(base_frame("", True), 650)
    add(base_frame("c", True), 160)
    add(base_frame("cb", True), 260)

    phases = (
        ("Running rules… 3002 files", 10),
        ("Preparing report…", 4),
    )
    tick_index = 0
    for message, frame_count in phases:
        for _ in range(frame_count):
            add(spinner_frame(SPINNER_TICKS[tick_index % len(SPINNER_TICKS)], message), 80)
            tick_index += 1

    add(report_frame(), 6500)
    output.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        output,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=1,
    )
    print(f"Rendered {output} ({output.stat().st_size} bytes, {len(frames)} frames)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "assets/media/code-buster-demo.gif",
    )
    arguments = parser.parse_args()
    render(arguments.output)


if __name__ == "__main__":
    main()
