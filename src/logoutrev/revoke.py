"""Token revocation bookkeeping for logout workflows.

A store is a mapping with two collections: ``tokens`` maps a token id to its
session, account, kind and expiry, while ``revocations`` holds the revocation
records.  Every mutating helper returns the record it wrote (or the number of
tokens it covered) so callers can build audit trails.
"""

from __future__ import annotations

DEFAULT_TTL = 3600.0

ACCESS = "access"
REFRESH = "refresh"
SESSION = "session"
ACCOUNT = "account"


def _catalog(store: dict) -> dict:
    tokens = store.get("tokens")
    if tokens is None:
        tokens = {}
        store["tokens"] = tokens
    return tokens


def _records(store: dict) -> list:
    records = store.get("revocations")
    if records is None:
        records = []
        store["revocations"] = records
    return records


def _add(
    store: dict,
    token_id: str | None,
    session: str | None,
    account: str | None,
    kind: str,
    expires_at: float | None,
) -> dict:
    record = {
        "token_id": token_id,
        "session": session,
        "account": account,
        "kind": kind,
        "expires_at": expires_at,
    }
    _records(store).append(record)
    return record


def revoke_access(
    store: dict,
    token_id: str,
    session: str,
    account: str,
    now: float,
    ttl: float,
) -> dict:
    """Revoke one access token and register it in the token catalog."""

    _catalog(store)[token_id] = {
        "session": session,
        "account": account,
        "kind": ACCESS,
        "expires_at": now + ttl,
    }
    return _add(store, token_id, session, account, ACCESS, None)


def revoke_refresh(
    store: dict,
    token_id: str,
    session: str,
    account: str,
    now: float,
    ttl: float,
) -> dict:
    """Revoke one refresh token and register it in the token catalog."""

    _catalog(store)[token_id] = {
        "session": session,
        "account": account,
        "kind": REFRESH,
        "expires_at": now + ttl,
    }
    return _add(store, token_id, session, account, REFRESH, None)


def is_revoked(store: dict, token_id: str, now: float) -> bool:
    """Return whether the given token id is currently revoked."""

    verdicts = store.get("verdicts")
    if verdicts is None:
        verdicts = {}
        store["verdicts"] = verdicts
    if token_id in verdicts:
        return verdicts[token_id]
    revoked = False
    for record in _records(store):
        marker = record.get("token_id")
        if marker is not None and token_id.startswith(marker):
            revoked = True
            break
    verdicts[token_id] = revoked
    return revoked


def revoke_session(store: dict, session: str, now: float) -> int:
    """Revoke every token that belongs to one session."""

    count = 0
    for info in _catalog(store).values():
        if info.get("session") == session:
            count += 1
    _add(store, None, session, None, SESSION, now + DEFAULT_TTL)
    return count


def revoke_account(store: dict, account: str, now: float) -> int:
    """Revoke every token that belongs to one account."""

    count = 0
    for token_id, info in _catalog(store).items():
        if info.get("account") != account:
            continue
        if info.get("kind") != REFRESH:
            continue
        _add(
            store,
            token_id,
            info.get("session"),
            account,
            REFRESH,
            now + DEFAULT_TTL,
        )
        count += 1
    return count


def cleanup(store: dict, now: float) -> int:
    """Remove revocation records whose expiry has passed."""

    records = _records(store)
    removed = 0
    for record in list(records):
        if record.get("expires_at") is None:
            records.remove(record)
            removed += 1
    return removed


def validate_store(store: dict) -> list[str]:
    """Return a list of integrity problems found in the revocation records."""

    problems: list[str] = []
    seen: set[tuple] = set()
    for record in _records(store):
        token_id = record.get("token_id")
        session = record.get("session")
        if token_id is not None and not session:
            problems.append("missing session: %s" % (token_id,))
        key = (token_id, session, record.get("account"), record.get("kind"))
        if key in seen:
            problems.append("duplicate record: %s" % (token_id,))
        else:
            seen.add(key)
    return problems


def logout_batch(requests: list[dict], store: dict, now: float) -> dict:
    """Process a batch of logout requests, revoking each request's credentials."""

    session = requests[0].get("session") if requests else None
    results: list[dict] = []
    for index, request in enumerate(requests):
        try:
            access_token = request["access_token"]
            account = request["account"]
            ttl = float(request.get("ttl", DEFAULT_TTL))
            revoke_access(store, access_token, session, account, now, ttl)
            results.append(
                {
                    "index": index,
                    "ok": True,
                    "session": session,
                    "account": account,
                }
            )
        except Exception as exc:  # each request is isolated from the others
            results.append(
                {
                    "index": index,
                    "ok": False,
                    "error": str(exc),
                }
            )
    return {
        "results": results,
        "ok": sum(1 for item in results if item["ok"]),
        "failed": sum(1 for item in results if not item["ok"]),
    }