#
# Zabbix MCP Server
# Copyright (C) 2026 initMAX s.r.o.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#

"""Fork: delegated Zabbix authentication ([server].delegated_auth, zabbix_mcp/delegation.py).

The end user's credential arrives in the _meta of a tools/call and every Zabbix
call of that tool goes out with it, never with the service api_token."""

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, "src")

from zabbix_utils.exceptions import APIRequestError  # noqa: E402

from zabbix_mcp.client import ClientManager, UnknownOutcomeError  # noqa: E402
from zabbix_mcp.config import AppConfig, ConfigError, ServerConfig, ZabbixServerConfig, load_config  # noqa: E402
from zabbix_mcp.delegation import (  # noqa: E402
    DELEGATED_AUTH_META_KEY, DelegatedAuthError, credential_from_meta, current_delegated_auth,
    reset_delegated_auth, set_delegated_auth,
)
from zabbix_mcp.server import ZabbixMCPServer, _register_tools  # noqa: E402

SESSION = "0123456789abcdef0123456789abcdef"


def _manager() -> ClientManager:
    cfg = AppConfig(server=ServerConfig(), zabbix_servers={"t": ZabbixServerConfig(
        name="t", url="http://zabbix.invalid", api_token="service-token", read_only=False)})
    return ClientManager(cfg)


class TestCredentialFromMeta(unittest.TestCase):
    def test_off_refuses_a_credential_instead_of_ignoring_it(self):
        with self.assertRaises(DelegatedAuthError) as ctx:
            credential_from_meta({DELEGATED_AUTH_META_KEY: SESSION}, "off")
        self.assertNotIn(SESSION, str(ctx.exception))

    def test_off_without_credential_is_the_upstream_behaviour(self):
        self.assertIsNone(credential_from_meta(None, "off"))
        self.assertIsNone(credential_from_meta({"other": 1}, "off"))

    def test_allowed(self):
        self.assertEqual(credential_from_meta({DELEGATED_AUTH_META_KEY: SESSION}, "allowed"), SESSION)
        self.assertIsNone(credential_from_meta({}, "allowed"))

    def test_required_refuses_a_call_without_credential(self):
        with self.assertRaises(DelegatedAuthError):
            credential_from_meta({}, "required")
        self.assertEqual(credential_from_meta({DELEGATED_AUTH_META_KEY: SESSION}, "required"), SESSION)

    def test_malformed_credential(self):
        for bad in ("short", "x" * 200, "abc def 0123456789abcdef", 12345, ["a"]):
            with self.subTest(bad=bad), self.assertRaises(DelegatedAuthError):
                credential_from_meta({DELEGATED_AUTH_META_KEY: bad}, "allowed")


class TestConfig(unittest.TestCase):
    def _load(self, extra: str):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(f'[server]\ntransport = "stdio"\n{extra}\n'
                            '[zabbix.t]\nurl = "http://z"\napi_token = "x"\n', encoding="utf-8")
            return load_config(str(path))

    def test_default_off(self):
        self.assertEqual(self._load("").server.delegated_auth, "off")

    def test_values(self):
        for mode in ("off", "allowed", "required"):
            self.assertEqual(self._load(f'delegated_auth = "{mode}"').server.delegated_auth, mode)

    def test_invalid(self):
        with self.assertRaises(ConfigError):
            self._load('delegated_auth = "yes"')


class TestClientManager(unittest.TestCase):
    def setUp(self):
        self.mgr = _manager()

    def _with_credential(self, fn):
        token = set_delegated_auth(SESSION)
        try:
            return fn()
        finally:
            reset_delegated_auth(token)

    def test_delegated_call_uses_the_user_credential_and_not_the_service_client(self):
        with patch.object(self.mgr, "call_with_session", return_value=[{"hostid": "1"}]) as cws, \
                patch.object(self.mgr, "_get_client", side_effect=AssertionError("service client used")):
            result = self._with_credential(lambda: self.mgr.call("t", "host.get", {"output": ["hostid"]}))
        self.assertEqual(result, [{"hostid": "1"}])
        cws.assert_called_once_with("t", "host.get", {"output": ["hostid"]}, SESSION)

    def test_without_credential_the_service_client_is_used(self):
        class FakeAPI:
            class host:
                @staticmethod
                def get(**kw):
                    return ["service"]
        with patch.object(self.mgr, "_get_client", return_value=FakeAPI()), \
                patch.object(self.mgr, "call_with_session", side_effect=AssertionError("delegated path used")):
            self.assertEqual(self.mgr.call("t", "host.get", {}), ["service"])

    def test_a_refused_session_is_never_retried_with_the_service_credential(self):
        refused = APIRequestError({"code": -32602, "message": "Invalid params.",
                                   "data": "Session terminated, re-login, please.", "body": {}})
        with patch.object(self.mgr, "call_with_session", side_effect=refused), \
                patch.object(self.mgr, "_get_client", side_effect=AssertionError("fallback to service")), \
                patch.object(self.mgr, "_reconnect", side_effect=AssertionError("fallback to service")):
            with self.assertRaises(APIRequestError):
                self._with_credential(lambda: self.mgr.call("t", "host.get", {}))

    def test_lost_answer_read_is_asked_again_write_is_not(self):
        with patch.object(self.mgr, "call_with_session", side_effect=[TimeoutError("t"), ["ok"]]) as cws:
            self.assertEqual(self._with_credential(lambda: self.mgr.call("t", "host.get", {})), ["ok"])
            self.assertEqual(cws.call_count, 2)
        with patch.object(self.mgr, "call_with_session", side_effect=TimeoutError("t")) as cws:
            with self.assertRaises(UnknownOutcomeError):
                self._with_credential(lambda: self.mgr.call("t", "host.update", {"hostid": "1"}))
            self.assertEqual(cws.call_count, 1)

    def test_method_format_is_still_checked(self):
        with self.assertRaises(ValueError):
            self._with_credential(lambda: self.mgr.call("t", "host.get/../x", {}))


class TestThroughTheProtocol(unittest.TestCase):
    """_meta sent by a real MCP client reaches ClientManager.call as the credential."""

    def _server(self, mode: str):
        mgr = _manager()
        mcp = ZabbixMCPServer(name="test")
        mcp.delegated_auth = mode
        _register_tools(mcp, mgr)
        return mgr, mcp

    def _run(self, mode: str, meta, tool="host_get", args=None, call_result=None):
        from mcp.client.client import Client
        mgr, mcp = self._server(mode)
        seen = []

        def fake_call(server, method, params, *a, **k):
            seen.append((method, current_delegated_auth()))
            return call_result if call_result is not None else [{"hostid": "10084", "host": "Zabbix server"}]

        async def go():
            async with Client(mcp) as client:
                return await client.call_tool(tool, args or {"output": ["host"]}, meta=meta)

        with patch.object(mgr, "call", side_effect=fake_call), \
                patch.object(mgr, "get_version", return_value="7.0.32"):
            result = asyncio.run(go())
        text = "\n".join(c.text for c in result.content if hasattr(c, "text"))
        return result.is_error, text, seen

    def test_credential_reaches_the_zabbix_call(self):
        is_error, text, seen = self._run("allowed", {DELEGATED_AUTH_META_KEY: SESSION})
        self.assertFalse(is_error, text)
        self.assertEqual(seen, [("host.get", SESSION)])
        self.assertIsNone(current_delegated_auth())   # not left behind after the call

    def test_without_meta_in_allowed_mode_no_credential(self):
        is_error, text, seen = self._run("allowed", None)
        self.assertFalse(is_error, text)
        self.assertEqual(seen, [("host.get", None)])

    def test_required_mode_refuses_before_any_zabbix_call(self):
        is_error, text, seen = self._run("required", None)
        self.assertTrue(is_error)
        self.assertIn("on behalf of a Zabbix user", text)
        self.assertEqual(seen, [])

    def test_off_mode_refuses_a_credential(self):
        is_error, text, seen = self._run("off", {DELEGATED_AUTH_META_KEY: SESSION})
        self.assertTrue(is_error)
        self.assertNotIn(SESSION, text)
        self.assertEqual(seen, [])

    def test_graph_render_checks_the_user_can_see_the_graph(self):
        is_error, text, seen = self._run("required", {DELEGATED_AUTH_META_KEY: SESSION},
                                         tool="graph_render", args={"graphid": "42"}, call_result=[])
        self.assertTrue(is_error)
        self.assertIn("no permission", text)
        self.assertEqual(seen, [("graph.get", SESSION)])


if __name__ == "__main__":
    unittest.main()
