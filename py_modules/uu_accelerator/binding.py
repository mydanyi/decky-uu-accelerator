"""Dependency-free rendering of the core's terminal-art QR into SVG.

The official core prints the pairing QR as UTF-8 plain text (the same art a
terminal would show): every character encodes *two vertical* QR modules via one
of four half-block glyphs plus an ASCII space, and rows are separated by LF::

    ' '      -> (white, white)
    '\\u2588' -> (black, black)   # full block
    '\\u2580' -> (black, white)   # upper half
    '\\u2584' -> (white, black)   # lower half

:func:`terminal_qr_svg` turns that text into a small, self-contained SVG built
*only* from the resulting integer matrix. Nothing from the source text is ever
echoed into the markup, so no character of the input can inject a tag or an
entity; anything that is not purely QR art (blank input, ``"Loading..."``,
markup, tabs, ...) yields an empty string.

Rendering rules (pinned by ``tests/test_binding.py``):

* The root lives in the SVG namespace and starts with ``<svg`` with a
  ``viewBox``; ``shape-rendering="crispEdges"`` keeps modules pixel-crisp.
* One QR module == one SVG user unit; each black module is a separate 1x1
  ``<rect>`` and a single white rect covers the whole canvas.
* A 4-module quiet border on every side (offset 4), so the canvas is the art's
  width plus 8 and twice its line count plus 8.
* Blank rows and leading/trailing blank columns are preserved: the canvas width
  equals the widest line and the height is twice the line count.
"""

__all__ = ["terminal_qr_svg"]

_FULL = "\u2588"
_UPPER = "\u2580"
_LOWER = "\u2584"

# terminal glyph -> (top pixel, bottom pixel); 1 == black, 0 == white
_GLYPHS = {
    " ": (0, 0),
    _FULL: (1, 1),
    _UPPER: (1, 0),
    _LOWER: (0, 1),
}

_LF = "\n"
_QUIET = 4  # QR minimum quiet zone, in modules, on every side


def terminal_qr_svg(text):
    """Render terminal-art ``text`` as a self-contained SVG string.

    Returns ``""`` for blank input, for any text carrying a character outside
    the legal QR alphabet (``' '``, the three half/full blocks and LF), and for
    any art that contains no black module at all.
    """
    if not isinstance(text, str) or not text:
        return ""

    for ch in text:
        if ch != _LF and ch not in _GLYPHS:
            return ""

    lines = text.splitlines()
    if not lines:
        return ""
    cols = max(len(line) for line in lines)
    if cols == 0:
        return ""

    rows = len(lines)
    width = cols + 2 * _QUIET
    height = 2 * rows + 2 * _QUIET

    black = []
    for row, line in enumerate(lines):
        top_y = _QUIET + 2 * row
        for col, ch in enumerate(line):
            top, bottom = _GLYPHS.get(ch, (0, 0))
            x = _QUIET + col
            if top:
                black.append((x, top_y))
            if bottom:
                black.append((x, top_y + 1))

    if not black:
        return ""

    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'width="{}" height="{}" viewBox="0 0 {} {}" '
        'shape-rendering="crispEdges">'.format(width, height, width, height),
        '<rect x="0" y="0" width="{}" height="{}" fill="#ffffff"/>'.format(
            width, height
        ),
    ]
    for x, y in black:
        parts.append(
            '<rect x="{}" y="{}" width="1" height="1" fill="#000000"/>'.format(
                x, y
            )
        )
    parts.append("</svg>")
    return "\n".join(parts)
