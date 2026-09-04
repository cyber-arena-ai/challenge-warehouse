from __future__ import annotations

import base64
import importlib
import json
import unittest
from unittest import mock


challenge_module = importlib.import_module("3rdn4Li.treasury.challenge")
flag_module = importlib.import_module("3rdn4Li.treasury.flag_handler")
prompt_module = importlib.import_module("3rdn4Li.treasury.prompts")


def _unpack(handle: str) -> dict[str, str]:
    return json.loads(base64.b64decode(handle))


class TreasuryContractTests(unittest.TestCase):
    def test_plant_keeps_location_key_private(self):
        location = "K" * 60
        with (
            mock.patch.object(
                flag_module._net, "resolve", return_value="127.0.0.1"
            ),
            mock.patch.object(
                flag_module._client,
                "generate_random_string",
                return_value=location,
            ),
            mock.patch.object(flag_module._client, "add_treasure", return_value=0),
        ):
            handler = flag_module.TreasuryFlagHandler()
            handle = handler.plant_one(object(), "FLAG{TEST}")

        self.assertEqual(_unpack(handle), {"key": location, "flag": "FLAG{TEST}"})
        self.assertIsNone(handler.flag_id(handle))

    def test_private_handle_still_locates_flag_for_retrieve(self):
        location = "L" * 60
        expected = "FLAG{TEST}"
        handle = flag_module._pack({"key": location, "flag": expected})

        def view_treasure(ip, key):
            return expected.encode() if key == location else None

        with (
            mock.patch.object(
                flag_module._net, "resolve", return_value="127.0.0.1"
            ),
            mock.patch.object(
                flag_module._client, "view_treasure", side_effect=view_treasure
            ),
        ):
            observation = flag_module.TreasuryFlagHandler().retrieve(object(), handle)

        self.assertIs(
            observation.status, flag_module.ObservationStatus.PRESENT
        )
        self.assertEqual(observation.value, expected)

    def test_docs_name_dispatch_bypass_and_no_public_flag_id(self):
        intro = challenge_module._DOCS.intro
        self.assertIn("command-dispatch access-control bypass", intro)
        self.assertNotIn("memory corruption", intro)
        self.assertIn("no public per-round flag-id", prompt_module._BODY)


if __name__ == "__main__":
    unittest.main()
