"""Guard the offline dashboard against missing color utilities."""

from pathlib import Path
import re
import unittest


class FrontendColorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (Path(__file__).resolve().parents[1] / 'frontend/index.html').read_text(encoding='utf-8')
        cls.css = source.split('<style>', 1)[1].split('</style>', 1)[0]
        cls.markup_and_script = source.split('</style>', 1)[1]

    def test_all_referenced_color_utilities_exist_offline(self):
        # Include JS templates: live status changes need the same offline styles.
        references = set(re.findall(
            r'(?<![\w-])(?:hover:|focus:)?(?:bg|text|border|placeholder)-'
            r'(?:[a-z]+-\d+(?:/\d+)?|transparent|none|white|black)',
            self.markup_and_script,
        ))
        selectors = {
            re.sub(r'\\(.)', r'\1', selector)
            for selector in re.findall(r'\.((?:\\.|[\w-])+)', self.css)
        }
        self.assertEqual(sorted(references - selectors), [])

    def test_secondary_copy_has_accessible_light_surface_contrast(self):
        def luminance(color):
            values = [int(color[i:i + 2], 16) / 255 for i in (0, 2, 4)]
            linear = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in values]
            return sum(v * weight for v, weight in zip(linear, (0.2126, 0.7152, 0.0722)))

        match = re.search(r'\.text-gray-400, \.text-slate-400\s*\{\s*color:\s*#([0-9a-f]{6})', self.css)
        self.assertIsNotNone(match)
        for background in ('ffffff', 'f8fafc', 'f1f5f9'):
            contrast = (luminance(background) + 0.05) / (luminance(match.group(1)) + 0.05)
            self.assertGreaterEqual(contrast, 4.5)

    def test_header_search_has_transparent_background_and_visible_placeholder(self):
        self.assertIn('.bg-transparent { background-color: transparent; }', self.css)
        self.assertIn('.pbi-title-bar input::placeholder { color: #cbd5e1;', self.css)


if __name__ == '__main__':
    unittest.main()
