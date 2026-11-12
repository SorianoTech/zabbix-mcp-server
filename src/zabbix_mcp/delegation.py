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

"""Delegated Zabbix authentication (fork customisation).

A trusted MCP client (the chat gateway behind the Zabbix frontend module) can
send, in the ``_meta`` of each ``tools/call``, the Zabbix credential of the end
user it acts for: a frontend session id or a personal API token. While that
call runs, every Zabbix API request goes out with that credential instead of
the ``api_token`` of ``[zabbix.<name>]``, so Zabbix itself applies the user's
host permissions, role restrictions and audit trail.

``[server].delegated_auth`` decides what is accepted:

* ``"off"`` (default) - a call that carries a credential is refused. It is
  never ignored: ignoring it would answer with the service account's rights.
* ``"allowed"`` - a call with a credential uses it; a call without one uses
  the configured service credential.
* ``"required"`` - a call without a credential is refused.

A delegated call never falls back to the service credential: when Zabbix
refuses the user's session (expired, no API access) the error is returned.
"""

from __future__ import annotations

import contextvars
import re
from typing import Any, Mapping

DELEGATED_AUTH_META_KEY = "zabbix-mcp/delegated-auth"
DELEGATED_AUTH_MODES = ("off", "allowed", "required")

# Zabbix session ids are 32 hex chars, API tokens 64; accept any plain token.
_CREDENTIAL_RE = re.compile(r"^[A-Za-z0-9]{16,128}$")

_delegated_auth: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "zabbix_delegated_auth", default=None,
)


class DelegatedAuthError(Exception):
    """A tools/call whose delegated credential does not fit the configured mode."""


def current_delegated_auth() -> str | None:
    """The end-user credential of the tool call being served, if any."""
    return _delegated_auth.get()


def set_delegated_auth(credential: str | None) -> contextvars.Token:
    return _delegated_auth.set(credential)


def reset_delegated_auth(token: contextvars.Token) -> None:
    _delegated_auth.reset(token)


def credential_from_meta(meta: Mapping[str, Any] | None, mode: str) -> str | None:
    """Validate the ``_meta`` of a tools/call against *mode*; return the credential or None.

    Raises DelegatedAuthError with a message fit for the caller (never containing
    the credential itself).
    """
    raw = meta.get(DELEGATED_AUTH_META_KEY) if meta else None
    if raw is None or raw == "":
        if mode == "required":
            raise DelegatedAuthError(
                "This server only answers on behalf of a Zabbix user: the call must carry the "
                f"user's credential in _meta['{DELEGATED_AUTH_META_KEY}'] ([server].delegated_auth = \"required\")."
            )
        return None
    if mode == "off":
        raise DelegatedAuthError(
            "The call carries a delegated Zabbix credential, but this server does not accept them "
            "([server].delegated_auth = \"off\"). It was refused rather than answered with the "
            "server's own Zabbix account."
        )
    if not isinstance(raw, str) or not _CREDENTIAL_RE.match(raw):
        raise DelegatedAuthError("The delegated Zabbix credential is malformed.")
    return raw
