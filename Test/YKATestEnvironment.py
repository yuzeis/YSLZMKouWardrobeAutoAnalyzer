import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import YKAEnvironment as environment


class EnvironmentTests(unittest.TestCase):
    def test_environment_reports_only_npcap_and_scapy_as_required(self) -> None:
        with mock.patch(
            "YKACapture.inspect_capture_environment",
            return_value={
                "backend_ready": True,
                "capture_probe": {"ready": True},
                "selected_interface_names": ["Meta"],
                "required_components": {
                    "npcap": {"installed": True, "ready": True},
                    "scapy": {"installed": True, "ready": True},
                },
            },
        ):
            result = environment.inspect_environment()
        self.assertTrue(result["ready"])
        self.assertEqual(result["missing"], [])
        self.assertEqual(set(result["required"]), {"npcap", "scapy"})
        self.assertFalse(result["optional"]["tshark"])
        self.assertFalse(result["optional"]["mergecap"])

    def test_download_rejects_non_official_url(self) -> None:
        with mock.patch.object(environment, "NPCAP_INSTALLER_URL", "http://example.invalid/npcap.exe"):
            with self.assertRaises(ValueError):
                environment.download_npcap_installer(Path("."))

    def test_download_verifies_signature_before_returning(self) -> None:
        class FakeResponse(io.BytesIO):
            headers = {"Content-Length": "4"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            environment.urllib.request, "urlopen", return_value=FakeResponse(b"test")
        ), mock.patch.object(environment, "_verify_authenticode", return_value=(True, "CN=Nmap")):
            result = environment.download_npcap_installer(Path(temp_dir))
            self.assertTrue(result.is_file())
            self.assertEqual(result.read_bytes(), b"test")

    def test_installer_launcher_has_no_silent_switch(self) -> None:
        source = Path(environment.__file__).read_text(encoding="utf-8")
        self.assertNotIn('"/S"', source)
        self.assertIn('"runas"', source)


if __name__ == "__main__":
    unittest.main()
