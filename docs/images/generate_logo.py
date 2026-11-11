#!/usr/bin/env python3
"""Rampart logo generator. Flat, single-colour mark: a hexagon whose top edge is a crenellated
wall, built from three brick courses. Wordmark is outlined from Red Hat Display (OFL)."""
import sys, os
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen

OUT = sys.argv[1]
BRAND, ACCENT, BRAND_ON_DARK, ACCENT_ON_DARK, INK = "#4353D6", "#19C3A6", "#8C98FF", "#2DD4BF", "#0F172A"

# ---- mark geometry (64 x 64 grid) -------------------------------------------------
# A regular flat-top hexagon split by a crenellation (square-wave) line into two interlocking pieces:
# the lower piece is the wall with three merlons, the upper piece is what it holds back.
CX, CY, S = 32.0, 32.0, 28.0
H = S * 3 ** 0.5 / 2
TOP, BOT = CY - H, CY + H
def xl(y): return (CX - S) + abs(y - CY) / H * (S / 2)
def xr(y): return (CX + S) - abs(y - CY) / H * (S / 2)
def pts(p): return " ".join(f"{x:.2f},{y:.2f}" for x, y in p)

def pieces(gap=3.6, yh=24.5, yl=38.5):
    g = gap / 2
    seg = 2 * S / 5
    x1, x2, x3, x4 = (CX - S) + seg, (CX - S) + 2 * seg, (CX - S) + 3 * seg, (CX - S) + 4 * seg
    lo_m, lo_c = yh + g, yl + g            # wall: merlon top, crenel floor
    up_m, up_c = yh - g, yl - g            # upper piece: over merlons, tooth tips
    lower = [(CX - S / 2, BOT), (CX - S, CY), (xl(lo_m), lo_m), (x1 - g, lo_m), (x1 - g, lo_c), (x2 + g, lo_c), (x2 + g, lo_m),
             (x3 - g, lo_m), (x3 - g, lo_c), (x4 + g, lo_c), (x4 + g, lo_m), (xr(lo_m), lo_m), (CX + S, CY), (CX + S / 2, BOT)]
    upper = [(CX - S / 2, TOP), (CX + S / 2, TOP), (xr(up_m), up_m), (x4 - g, up_m), (x4 - g, up_c), (x3 + g, up_c), (x3 + g, up_m),
             (x2 - g, up_m), (x2 - g, up_c), (x1 + g, up_c), (x1 + g, up_m), (xl(up_m), up_m)]
    return lower, upper

def mark_svg(wall, sky, gap=3.6, r=1.4):
    lower, upper = pieces(gap)
    poly = lambda p, c: f'<polygon points="{pts(p)}" fill="{c}" stroke="{c}" stroke-width="{r}" stroke-linejoin="round"/>'
    return poly(upper, sky) + poly(lower, wall)

# ---- wordmark outlines ---------------------------------------------------------------
def wordmark(text, size, x0, baseline, tracking=0.0, wght=800):
    f = TTFont("/usr/share/fonts/redhat-vf/RedHatDisplay[wght].ttf")
    f = instantiateVariableFont(f, {"wght": wght})
    gs, cmap, upm = f.getGlyphSet(), f.getBestCmap(), f["head"].unitsPerEm
    sc = size / upm
    x, d = x0, []
    for ch in text:
        g = cmap[ord(ch)]
        pen = SVGPathPen(gs, lambda v: f"{v:.2f}")
        gs[g].draw(TransformPen(pen, (sc, 0, 0, -sc, x, baseline)))
        d.append(pen.getCommands())
        x += gs[g].width * sc + tracking
    return " ".join(d), x - tracking

def write(name, body, w, h, label="Rampart"):
    with open(os.path.join(OUT, name), "w") as fh:
        fh.write(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="{label}">{body}</svg>\n')

wm, xend = wordmark("rampart", 50, 78, 47.0, tracking=-0.6)
W = round(xend + 6)
def lockup(wall, sky, ink):
    return f'{mark_svg(wall, sky)}<path d="{wm}" fill="{ink}"/>'

write("logo.svg", lockup(BRAND, ACCENT, INK), W, 64)
write("logo-dark.svg", lockup(BRAND_ON_DARK, ACCENT_ON_DARK, "#FFFFFF"), W, 64)
write("logo-mono.svg", lockup("currentColor", "currentColor", "currentColor"), W, 64)
write("logo-mark.svg", mark_svg(BRAND, ACCENT), 64, 64)
write("logo-mark-dark.svg", mark_svg(BRAND_ON_DARK, ACCENT_ON_DARK), 64, 64)
write("logo-mark-mono.svg", mark_svg("currentColor", "currentColor"), 64, 64)
write("favicon.svg", mark_svg(BRAND, ACCENT, gap=5.0, r=1.0), 64, 64)
print("W", W)
