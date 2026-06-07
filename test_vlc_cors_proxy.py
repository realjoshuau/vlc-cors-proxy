from __future__ import annotations

import unittest
from unittest.mock import patch

import vlc_cors_proxy


class AllowedOriginTests(unittest.TestCase):
    def test_origin_regex_allows_apex_and_nested_subdomains(self) -> None:
        origin_re = vlc_cors_proxy.build_origin_regex("example.com")

        allowed = [
            "https://example.com",
            "http://example.com",
            "https://www.example.com",
            "https://a.b.example.com",
            "https://example.com:3000",
        ]
        for origin in allowed:
            with self.subTest(origin=origin):
                self.assertIsNotNone(origin_re.match(origin))

    def test_origin_regex_rejects_wrong_origins(self) -> None:
        origin_re = vlc_cors_proxy.build_origin_regex("example.com")

        rejected = [
            "https://badexample.com",
            "https://example.com.evil.test",
            "ftp://example.com",
        ]
        for origin in rejected:
            with self.subTest(origin=origin):
                self.assertIsNone(origin_re.match(origin))

    def test_allowed_origin_must_be_hostname_only(self) -> None:
        rejected = [
            "https://example.com",
            "example.com:3000",
            "example.com/path",
            "*.example.com",
            "example..com",
        ]
        for domain in rejected:
            with self.subTest(domain=domain):
                with self.assertRaises(ValueError):
                    vlc_cors_proxy.build_origin_regex(domain)

    def test_allowed_origin_arg_is_required(self) -> None:
        with patch("sys.argv", ["vlc_cors_proxy.py"]):
            with self.assertRaises(SystemExit):
                vlc_cors_proxy.parse_args()

    def test_allowed_origin_arg_is_accepted(self) -> None:
        with patch("sys.argv", ["vlc_cors_proxy.py", "--allowed-origin", "example.com"]):
            args = vlc_cors_proxy.parse_args()

        self.assertEqual(args.allowed_origin, "example.com")


if __name__ == "__main__":
    unittest.main()
