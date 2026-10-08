"""Render evidence figures from the checked Week 3 processing outputs."""

import csv
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "images"
OUT.mkdir(exist_ok=True)
FONT_DIR = Path("C:/Windows/Fonts")


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONT_DIR / name), size)


def rounded(draw: ImageDraw.ImageDraw, box, radius, fill, outline=None, width=1):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def base(title: str, subtitle: str):
    image = Image.new("RGB", (1600, 1000), "#f4f7fb")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 1600, 12), fill="#1d4ed8")
    draw.text((76, 58), "CTI LAB  /  WEEK 03", font=font("segoeui.ttf", 20), fill="#2563eb")
    draw.text((76, 108), title, font=font("segoeuib.ttf", 42), fill="#111827")
    draw.text((76, 174), subtitle, font=font("segoeui.ttf", 22), fill="#64748b")
    return image, draw


def render_processing():
    summary = json.loads((ROOT / "data" / "processing-summary.json").read_text(encoding="utf-8"))
    with (ROOT / "data" / "normalized_iocs.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))

    image, draw = base("Filtering and normalization", "Verified output generated from the included raw IOC sample")
    cards = [
        ("INPUT RECORDS", summary["input_records"], "#dbeafe", "#1d4ed8"),
        ("UNIQUE VALID", summary["valid_unique_indicators"], "#dcfce7", "#15803d"),
        ("DUPLICATES REMOVED", summary["duplicates_removed"], "#fef3c7", "#b45309"),
        ("INVALID FILTERED", summary["invalid_records_filtered"], "#fee2e2", "#b91c1c"),
    ]
    for i, (label, value, fill, ink) in enumerate(cards):
        x = 76 + i * 365
        rounded(draw, (x, 245, x + 330, 360), 18, "white", "#e2e8f0", 2)
        draw.text((x + 24, 266), label, font=font("segoeuib.ttf", 16), fill="#64748b")
        draw.text((x + 24, 295), str(value), font=font("segoeuib.ttf", 38), fill=ink)
        draw.ellipse((x + 267, 277, x + 303, 313), fill=fill)

    left, top = 76, 410
    widths = [140, 170, 680, 200]
    headers = ["TYPE", "RECORD", "NORMALIZED VALUE", "TO_IDS"]
    table_w = sum(widths)
    rounded(draw, (left, top, left + table_w, top + 386), 16, "white", "#dbe3ef", 2)
    draw.rounded_rectangle((left, top, left + table_w, top + 62), radius=16, fill="#eef2ff")
    draw.rectangle((left, top + 44, left + table_w, top + 62), fill="#eef2ff")
    x = left
    for hdr, width in zip(headers, widths):
        draw.text((x + 18, top + 20), hdr, font=font("segoeuib.ttf", 15), fill="#475569")
        x += width
    for row_i, row in enumerate(rows):
        y = top + 62 + row_i * 78
        if row_i % 2 == 1:
            draw.rectangle((left + 2, y, left + table_w - 2, y + 77), fill="#fafcff")
        vals = [row["type"], row["record_id"], row["value"], row["to_ids"]]
        x = left
        for value, width in zip(vals, widths):
            draw.text((x + 18, y + 27), value, font=font("segoeui.ttf", 18), fill="#0f172a")
            x += width
        draw.line((left, y + 77, left + table_w, y + 77), fill="#e2e8f0", width=1)

    draw.text((76, 850), "Synthetic training indicators only. Reserved examples; not evidence of malicious activity.", font=font("segoeui.ttf", 18), fill="#64748b")
    draw.text((76, 901), "Source: normalized_iocs.csv  |  processing-summary.json", font=font("segoeui.ttf", 15), fill="#94a3b8")
    image.save(OUT / "01-processing-results.png", optimize=True)


def render_misp():
    data = json.loads((ROOT / "data" / "misp-event.json").read_text(encoding="utf-8"))
    event = data["Event"]
    attrs = event["Attribute"]

    image, draw = base("Imported MISP event", "Event 1 verified in the local MISP interface")
    rounded(draw, (76, 245, 1524, 340), 16, "#fff7ed", "#fed7aa", 2)
    draw.text((104, 267), "IMPORT CONFIRMED  /  EVENT ID 1", font=font("segoeuib.ttf", 19), fill="#15803d")
    draw.text((104, 303), "MISP showed Event created; event is unpublished and organization-only.", font=font("segoeui.ttf", 20), fill="#166534")

    rounded(draw, (76, 375, 1524, 510), 16, "white", "#dbe3ef", 2)
    draw.text((108, 402), "EVENT", font=font("segoeuib.ttf", 16), fill="#64748b")
    draw.text((108, 438), event["info"], font=font("segoeuib.ttf", 23), fill="#111827")
    draw.text((108, 480), f"Date: {event['date']}    |    Analysis: {event['analysis']}    |    Threat level: {event['threat_level_id']}    |    Distribution: {event['distribution']}", font=font("segoeui.ttf", 17), fill="#475569")

    left, top = 76, 550
    widths = [230, 650, 250, 200]
    headers = ["MISP TYPE", "ATTRIBUTE VALUE", "CATEGORY", "TO_IDS"]
    table_w = sum(widths)
    rounded(draw, (left, top, left + table_w, top + 320), 16, "white", "#dbe3ef", 2)
    draw.rounded_rectangle((left, top, left + table_w, top + 58), radius=16, fill="#eef2ff")
    draw.rectangle((left, top + 40, left + table_w, top + 58), fill="#eef2ff")
    x = left
    for hdr, width in zip(headers, widths):
        draw.text((x + 18, top + 19), hdr, font=font("segoeuib.ttf", 15), fill="#475569")
        x += width
    for row_i, attr in enumerate(attrs):
        y = top + 58 + row_i * 65
        if row_i % 2 == 1:
            draw.rectangle((left + 2, y, left + table_w - 2, y + 64), fill="#fafcff")
        vals = [attr["type"], attr["value"], attr["category"], str(attr["to_ids"]).lower()]
        x = left
        for value, width in zip(vals, widths):
            draw.text((x + 18, y + 21), value, font=font("segoeui.ttf", 17), fill="#0f172a")
            x += width
        draw.line((left, y + 64, left + table_w, y + 64), fill="#e2e8f0", width=1)

    draw.text((76, 918), f"Source: verified MISP event view + data/misp-event.json  |  {len(attrs)} benign training attributes  |  all to_ids=false", font=font("segoeui.ttf", 16), fill="#64748b")
    image.save(OUT / "02-misp-import-payload.png", optimize=True)


if __name__ == "__main__":
    render_processing()
    render_misp()
    print(f"Rendered evidence figures to {OUT}")
