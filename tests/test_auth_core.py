import unittest

from fastapi import Request

from app_support.auth_core import get_auth_cookie_params


class AuthCoreCookieTests(unittest.TestCase):
    def _request(self, *, host: str, forwarded_host: str | None = None, forwarded_proto: str | None = None) -> Request:
        headers = [(b"host", host.encode("utf-8"))]
        if forwarded_host is not None:
            headers.append((b"x-forwarded-host", forwarded_host.encode("utf-8")))
        if forwarded_proto is not None:
            headers.append((b"x-forwarded-proto", forwarded_proto.encode("utf-8")))
        return Request(
            {
                "type": "http",
                "scheme": "http",
                "server": ("testserver", 80),
                "client": ("127.0.0.1", 12345),
                "method": "GET",
                "path": "/web",
                "raw_path": b"/web",
                "query_string": b"",
                "headers": headers,
            }
        )

    def test_uses_configured_cookie_domain_for_matching_forwarded_host(self):
        request = self._request(
            host="127.0.0.1:8000",
            forwarded_host="desk.example.com:443",
            forwarded_proto="https",
        )

        params = get_auth_cookie_params(
            request,
            access_token_cookie_max_age=3600,
            auth_cookie_domain="example.com",
        )

        self.assertEqual(params["domain"], ".example.com")
        self.assertTrue(params["secure"])

    def test_skips_configured_cookie_domain_for_other_hosts(self):
        request = self._request(
            host="adminvps.local:8000",
            forwarded_host="adminvps.local:443",
            forwarded_proto="https",
        )

        params = get_auth_cookie_params(
            request,
            access_token_cookie_max_age=3600,
            auth_cookie_domain="example.com",
        )

        self.assertIsNone(params["domain"])
        self.assertTrue(params["secure"])

    def test_servora_fallback_ignores_port_in_forwarded_host(self):
        request = self._request(
            host="127.0.0.1:8000",
            forwarded_host="desk.servora.ru:443",
            forwarded_proto="https",
        )

        params = get_auth_cookie_params(
            request,
            access_token_cookie_max_age=3600,
        )

        self.assertEqual(params["domain"], ".servora.ru")


if __name__ == "__main__":
    unittest.main()
