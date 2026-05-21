"""
Unit tests for the log line parser.

Feeds the worst-case malformed inputs possible and asserts graceful
degradation — the parser must never raise an exception; it either returns
a valid dict or None.
"""

import json
import pytest
from parser import parse_line


# ---------------------------------------------------------------------------
# Normal / well-formed lines
# ---------------------------------------------------------------------------

class TestNormalLines:
    def test_iso_timestamp(self):
        line = "2024-03-15T14:23:01Z 192.168.1.42 GET /api/users 200 142ms"
        r = parse_line(line)
        assert r is not None
        assert r["ip"] == "192.168.1.42"
        assert r["method"] == "GET"
        assert r["path"] == "/api/users"
        assert r["status"] == 200
        assert r["response_ms"] == pytest.approx(142.0)
        assert r["epoch_ms"] is not None

    def test_slash_timestamp(self):
        line = "2024/03/15 14:23:01 10.0.0.7 POST /api/login 401 89ms"
        r = parse_line(line)
        assert r is not None
        assert r["status"] == 401
        assert r["epoch_ms"] is not None

    def test_day_mon_year_timestamp(self):
        line = "15-Mar-2024 14:23:01 192.168.1.1 GET /health 200 10ms"
        r = parse_line(line)
        assert r is not None
        assert r["method"] == "GET"
        assert r["epoch_ms"] is not None

    def test_unix_epoch_timestamp(self):
        line = "1710512581 192.168.1.1 GET /api/users 200 50ms"
        r = parse_line(line)
        assert r is not None
        assert r["epoch_ms"] is not None

    def test_response_time_seconds(self):
        line = "2024-03-15T14:23:01Z 192.168.1.1 GET /slow 200 0.142s"
        r = parse_line(line)
        assert r is not None
        assert r["response_ms"] == pytest.approx(142.0, rel=1e-3)

    def test_response_time_bare_number(self):
        line = "2024-03-15T14:23:01Z 192.168.1.1 GET /api 200 500"
        r = parse_line(line)
        assert r is not None
        assert r["response_ms"] == pytest.approx(500.0)

    def test_extra_user_agent_field(self):
        line = '2024-03-15T14:23:01Z 192.168.1.1 GET /api/users 200 142ms "Mozilla/5.0"'
        r = parse_line(line)
        assert r is not None
        assert r["status"] == 200

    def test_extra_referrer_with_spaces(self):
        line = (
            '2024-03-15T14:23:01Z 10.0.0.1 GET /page 200 55ms '
            '"https://example.com/referrer page"'
        )
        r = parse_line(line)
        assert r is not None
        assert r["ip"] == "10.0.0.1"

    def test_all_http_methods(self):
        for method in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            line = f"2024-03-15T14:23:01Z 1.2.3.4 {method} /x 200 10ms"
            r = parse_line(line)
            assert r is not None, f"Failed for method {method}"
            assert r["method"] == method

    def test_path_with_query_string(self):
        line = "2024-03-15T14:23:01Z 1.2.3.4 GET /search?q=test&page=2 200 20ms"
        r = parse_line(line)
        assert r is not None
        assert "search" in r["path"]


# ---------------------------------------------------------------------------
# Edge cases — missing / corrupt fields
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_missing_status_dash_returns_none_not_raises(self):
        """
        Lines with '-' status must produce status=None.
        Without the guard at parser.py:131, int('-') raises ValueError and
        crashes the entire ingestion loop for the whole file.
        """
        line = "2024-03-15T14:23:01Z 192.168.1.1 GET /api/users - 142ms"
        r = parse_line(line)
        assert r is not None, "Row with '-' status should be kept, not dropped"
        assert r["status"] is None
        assert r["ip"] == "192.168.1.1"
        assert r["response_ms"] is not None

    def test_empty_line(self):
        assert parse_line("") is None

    def test_whitespace_only(self):
        assert parse_line("   \t  \n") is None

    def test_completely_malformed(self):
        assert parse_line("WARN: disk usage above 80%") is None

    def test_partial_log_write(self):
        assert parse_line("2024-03-15T14:23:01Z PARTIAL LOG WRITE") is None

    def test_java_stack_trace(self):
        assert parse_line("\tat com.example.App.run(App.java:42)") is None

    def test_blank_line_in_stack_trace(self):
        assert parse_line("Exception in thread main java.lang.NullPointerException") is None

    def test_path_with_numeric_id(self):
        line = "2024-03-15T14:23:01Z 10.0.0.99 GET /api/users/12345 200 55ms"
        r = parse_line(line)
        assert r is not None
        assert r["path"] == "/api/users/12345"

    def test_very_long_path_does_not_raise(self):
        long_path = "/api/" + "A" * 5000
        line = f"2024-03-15T14:23:01Z 1.2.3.4 GET {long_path} 200 10ms"
        r = parse_line(line)
        # May or may not parse depending on regex limits — must not raise
        assert r is None or isinstance(r, dict)

    def test_leading_whitespace(self):
        line = "  2024-03-15T14:23:01Z 192.168.1.1 GET /api 200 10ms"
        r = parse_line(line)
        assert r is not None


# ---------------------------------------------------------------------------
# JSON log lines
# ---------------------------------------------------------------------------

class TestJsonLines:
    def test_standard_json(self):
        line = json.dumps({
            "timestamp": "2024-03-15T14:23:01Z",
            "ip": "192.168.1.42",
            "method": "POST",
            "path": "/api/login",
            "status": 200,
            "response_time": "89ms",
        })
        r = parse_line(line)
        assert r is not None
        assert r["ip"] == "192.168.1.42"
        assert r["status"] == 200

    def test_json_alias_keys(self):
        """remote_addr / uri / status_code / latency should all resolve."""
        line = json.dumps({
            "ts": "2024-03-15T14:23:01Z",
            "remote_addr": "10.0.0.1",
            "method": "GET",
            "uri": "/api/orders",
            "status_code": 404,
            "latency": "23ms",
        })
        r = parse_line(line)
        assert r is not None
        assert r["ip"] == "10.0.0.1"
        assert r["status"] == 404

    def test_json_missing_ip_returns_none(self):
        line = json.dumps({"status": 200, "path": "/api/users"})
        assert parse_line(line) is None

    def test_json_missing_status_returns_none(self):
        line = json.dumps({"ip": "1.2.3.4", "path": "/x"})
        assert parse_line(line) is None

    def test_invalid_json_brace(self):
        assert parse_line("{bad json: [}") is None

    def test_json_array_not_object(self):
        assert parse_line("[1, 2, 3]") is None

    def test_json_nested_object_does_not_raise(self):
        line = json.dumps({"ip": "1.2.3.4", "status": 500, "meta": {"key": "value"}})
        r = parse_line(line)
        # Should either parse or return None — must not raise
        assert r is None or isinstance(r, dict)


# ---------------------------------------------------------------------------
# All status code families
# ---------------------------------------------------------------------------

class TestStatusCodes:
    @pytest.mark.parametrize("code", [200, 201, 204])
    def test_2xx(self, code):
        r = parse_line(f"2024-03-15T14:23:01Z 1.2.3.4 GET /x {code} 10ms")
        assert r is not None and r["status"] == code

    @pytest.mark.parametrize("code", [301, 302, 304])
    def test_3xx(self, code):
        r = parse_line(f"2024-03-15T14:23:01Z 1.2.3.4 GET /x {code} 10ms")
        assert r is not None and r["status"] == code

    @pytest.mark.parametrize("code", [400, 401, 403, 404])
    def test_4xx(self, code):
        r = parse_line(f"2024-03-15T14:23:01Z 1.2.3.4 GET /x {code} 10ms")
        assert r is not None and r["status"] == code

    @pytest.mark.parametrize("code", [500, 502, 503])
    def test_5xx(self, code):
        r = parse_line(f"2024-03-15T14:23:01Z 1.2.3.4 GET /x {code} 10ms")
        assert r is not None and r["status"] == code


# ---------------------------------------------------------------------------
# Timestamp format round-trips
# ---------------------------------------------------------------------------

class TestTimestamps:
    def test_iso_sets_epoch(self):
        r = parse_line("2024-03-15T14:23:01Z 1.2.3.4 GET /x 200 10ms")
        assert r["epoch_ms"] == pytest.approx(1710512581000.0, rel=1e-3)

    def test_unix_epoch_matches_iso(self):
        iso = parse_line("2024-03-15T14:23:01Z 1.2.3.4 GET /x 200 10ms")
        epoch = parse_line("1710512581 1.2.3.4 GET /x 200 10ms")
        assert iso["epoch_ms"] == pytest.approx(epoch["epoch_ms"], rel=1e-3)

    def test_unparseable_timestamp_gives_none_not_raise(self):
        line = "NOTADATE 1.2.3.4 GET /x 200 10ms"
        r = parse_line(line)
        # Primary regex may not match, returning None — that is acceptable
        assert r is None or r.get("epoch_ms") is None
