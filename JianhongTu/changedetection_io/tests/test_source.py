from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path
from xml.etree import ElementTree


_SOURCE_PATH = Path(__file__).parents[1] / "_source.py"
_SPEC = importlib.util.spec_from_file_location(
    "changedetection_probe_source", _SOURCE_PATH
)
assert _SPEC is not None and _SPEC.loader is not None
_SOURCE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SOURCE)

_SELECTOR_RE = re.compile(
    r"^xpath:(?:string|normalize-space)\("
    r"//(?P<section_tag>[a-z]+)\[@(?P<section_attribute>[a-z-]+)='"
    r"(?P<section_value>[^']+)'\]"
    r"(?P<step>//|/)"
    r"(?P<field_tag>[a-z]+)\[@(?P<field_attribute>[a-z-]+)='"
    r"(?P<field_value>[^']+)'\]\)$"
)


class SourceWorkflowTests(unittest.TestCase):
    def test_probe_document_makes_passthrough_observably_wrong(self) -> None:
        for index in range(100):
            marker = f"selected marker {index}"
            _section, selector, layout = _SOURCE._fresh_page(marker)
            with self.subTest(index=index, selector=selector):
                match = _SELECTOR_RE.fullmatch(selector)
                self.assertIsNotNone(match)
                assert match is not None

                body = ElementTree.fromstring(f"<body>{layout}</body>")
                selected_sections = [
                    element
                    for element in body.iter(match["section_tag"])
                    if element.get(match["section_attribute"])
                    == match["section_value"]
                ]
                self.assertEqual(len(selected_sections), 1)
                selected_section = selected_sections[0]
                field_candidates = (
                    list(selected_section)
                    if match["step"] == "/"
                    else list(selected_section.iter())
                )
                selected_fields = [
                    element
                    for element in field_candidates
                    if element.tag == match["field_tag"]
                    and element.get(match["field_attribute"])
                    == match["field_value"]
                ]
                self.assertEqual(len(selected_fields), 1)
                self.assertEqual(
                    "".join(selected_fields[0].itertext()).strip(), marker
                )

                section_text = " ".join(selected_section.itertext()).strip()
                body_text = " ".join(body.itertext()).strip()
                self.assertNotEqual(section_text, marker)
                self.assertNotEqual(body_text, marker)


if __name__ == "__main__":
    unittest.main()
