"""Contract tests for py_modules/uu_accelerator/binding.py.

``binding.py`` does not exist yet, so this module is expected to be red until
``terminal_qr_svg`` is implemented. The helper is imported defensively: a
missing module (or a missing symbol) must surface as a clear per-test failure,
never as a collection error that hides every other test in the suite.

The API is a single, dependency-free, *trusted* transform::

    terminal_qr_svg(text) -> str

It turns the terminal-art QR the core prints (each character encodes two
vertical QR pixels) into a small, self-contained SVG built **only** from the
resulting integer matrix. The text is never echoed into the markup verbatim, so
no character of the input can inject tags or entities.

The raw file observed on device is UTF-8 plain text whose only glyphs are
``' '``, ``'\\u2588'`` (full block), ``'\\u2580'`` (upper half) and ``'\\u2584'``
(lower half), plus LF. Mapping (two vertical pixels per character):

    ' ' -> (white, white)
    '\\u2588' -> (black, black)
    '\\u2580' -> (black, white)
    '\\u2584' -> (white, black)

Rendering rules pinned here:

* SVG root lives in the SVG namespace and starts with ``<svg``.
* ``shape-rendering="crispEdges"`` so pixels never blur.
* One QR module == one SVG user unit; every black module is a 1x1 ``<rect>``.
* A 4-module quiet border on every side (a quiet zone of 4 is the QR minimum);
  black modules therefore start at coordinate 4.
* A white background rect covers the whole canvas.
* Blank rows and trailing/leading blank columns are *preserved*: the canvas
  width equals the input's character-column count and the height is twice the
  input's line count. Nothing is stripped.
* Blank input, non-QR text such as ``"Loading..."`` and anything containing
  markup or otherwise illegal characters yields an empty string.

Run with:
    PYTHONPATH=py_modules python3 -m unittest discover -s tests -v
"""

import unittest
import xml.etree.ElementTree as ET

try:  # discover() imports test modules either package-qualified or flat
    from uu_accelerator.binding import terminal_qr_svg
    _IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - red until binding.py exists
    terminal_qr_svg = None
    _IMPORT_ERROR = exc

_BLACK = {"#000", "#000000", "black", "rgb(0,0,0)"}
_WHITE = {"#fff", "#ffffff", "white", "rgb(255,255,255)"}

# two vertical QR pixels encoded by each terminal glyph
BLOCK = "\u2588"
UPPER = "\u2580"
LOWER = "\u2584"


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _num(value):
    """Parse a numeric SVG attribute, tolerating a unit suffix ("12px")."""
    if value is None:
        return None
    cleaned = "".join(ch for ch in str(value) if ch.isdigit() or ch in "+-.e")
    return float(cleaned) if cleaned not in ("", "+", "-", ".") else None


def _fill(el):
    value = el.get("fill")
    if value is None:
        for chunk in (el.get("style") or "").split(";"):
            key, sep, item = chunk.partition(":")
            if sep and key.strip() == "fill":
                value = item.strip()
                break
    return (value or "").strip().lower()


def _rects(root):
    rects = []
    for el in root.iter():
        if _local(el.tag) != "rect":
            continue
        x = _num(el.get("x"))
        y = _num(el.get("y"))
        w = _num(el.get("width"))
        h = _num(el.get("height"))
        rects.append(
            (x if x is not None else 0.0, y if y is not None else 0.0,
             w if w is not None else 0.0, h if h is not None else 0.0, _fill(el))
        )
    return rects


def _dims(root):
    viewbox = root.get("viewBox") or root.get("viewbox")
    if viewbox:
        parts = viewbox.replace(",", " ").split()
        return _num(parts[2]), _num(parts[3])
    return _num(root.get("width")), _num(root.get("height"))


class TerminalQrSvgTests(unittest.TestCase):
    def setUp(self):
        if terminal_qr_svg is None:
            self.fail(
                "uu_accelerator.binding.terminal_qr_svg 尚未实现: {!r}".format(
                    _IMPORT_ERROR)
            )

    def _svg(self, text):
        svg = terminal_qr_svg(text)
        self.assertIsInstance(svg, str)
        return svg

    def _black_cells(self, root):
        black = [(x, y, w, h) for x, y, w, h, fill in _rects(root)
                 if fill in _BLACK]
        for _, _, w, h in black:
            self.assertEqual((w, h), (1.0, 1.0), "black modules must be 1x1")
        return sorted((int(x), int(y)) for x, y, _, _ in black)

    def test_maps_terminal_blocks_to_qr_pixels(self):
        # '▀'=(black,white) '▄'=(white,black) '█'=black ' '=white, one row wide.
        svg = self._svg(UPPER + LOWER + BLOCK + " ")
        self.assertTrue(svg.startswith("<svg"))
        self.assertIn("crispEdges", svg)

        root = ET.fromstring(svg)
        width, height = _dims(root)
        # 4 character columns + 4 quiet modules on each side.
        self.assertEqual(width, 12.0)
        self.assertEqual(height, 10.0)

        cells = self._black_cells(root)
        self.assertEqual(
            cells,
            [(4, 4), (5, 5), (6, 4), (6, 5)],
            "each glyph must render its two vertical pixels at offset 4+",
        )

        # Quiet zone: no black module may intrude on the 4-module border.
        for x, y in cells:
            self.assertGreaterEqual(x, 4)
            self.assertGreaterEqual(y, 4)
            self.assertLess(x, width - 4)
            self.assertLess(y, height - 4)

        # A white background must cover the whole canvas.
        whites = [(x, y, w, h) for x, y, w, h, fill in _rects(root)
                  if fill in _WHITE]
        self.assertTrue(
            any(w == width and h == height for _, _, w, h in whites),
            "a full-canvas white background rect is required",
        )

    def test_preserves_blank_rows_and_trailing_columns(self):
        # A blank leading row, a black cell with a trailing blank column, and a
        # blank trailing row: nothing may be trimmed.
        svg = self._svg("  \n" + BLOCK + " \n  ")
        root = ET.fromstring(svg)
        width, height = _dims(root)
        self.assertEqual(width, 10.0)   # 2 character columns (trailing space kept)
        self.assertEqual(height, 14.0)  # 3 lines x 2 vertical pixels each

        self.assertEqual(self._black_cells(root), [(4, 6), (4, 7)])

    def test_invalid_and_injection_inputs_produce_no_svg(self):
        cases = [
            "",
            "   ",
            "\n",
            "   \n   \n",
            "Loading...",
            "loading",
            "<svg></svg>",
            "<script>alert(1)</script>",
            BLOCK + "<script>alert(1)</script>",
            "a&b",
            "abc",
            UPPER + LOWER + BLOCK + "\tx",
        ]
        for bad in cases:
            with self.subTest(bad=bad):
                self.assertEqual(self._svg(bad), "")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
