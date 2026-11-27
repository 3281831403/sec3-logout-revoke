"""Token revocation bookkeeping for logout workflows.

A store is a mapping with two collections: ``tokens`` maps a token id to its
session, account, kind and expiry, while ``revocations`` holds the revocation
records.  Every mutating helper returns the record it wrote (or the number of
tokens it covered) so callers can build audit trails.

A logout has to revoke both halves of a session: revoking only the access
token leaves the refresh token able to mint fresh credentials, which defeats
the logout.  Revocation records carry an expiry and are pruned by
:func:`cleanup`, and writing the same revocation twice is idempotent so a
repeated logout never grows the record list.
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


def _key(record: dict) -> tuple:
    return (
        record.get("token_id"),
        record.get("session"),
        record.get("account"),
        record.get("kind"),
    )


def _add(
    store: dict,
    token_id: str | None,
    session: str | None,
    account: str | None,
    kind: str,
    expires_at: float | None,
) -> dict:
    """Record one revocation, idempotently.

    A repeated logout must not append a second record for the same
    ``(token, session, account, kind)`` tuple: the existing record is returned
    instead.  Its expiry is only ever extended, so replaying an older request
    can never shorten a revocation that is already in force.
    """

    wanted = (token_id, session, account, kind)
    for existing in _records(store):
        if _key(existing) != wanted:
            continue
        old = existing.get("expires_at")
        if old is None or (expires_at is not None and expires_at > old):
            existing["expires_at"] = expires_at
        return existing

    record = {
        "token_id": token_id,
        "session": session,
        "account": account,
        "kind": kind,
        "expires_at": expires_at,
    }
    _records(store).append(record)
    return record


def _register(
    store: dict,
    token_id: str,
    session: str | None,
    account: str | None,
    kind: str,
    now: float,
    ttl: float,
) -> None:
    _catalog(store)[token_id] = {
        "session": session,
        "account": account,
        "kind": kind,
        "expires_at": now + ttl,
    }


def revoke_access(
    store: dict,
    token_id: str,
    session: str,
    account: str,
    now: float,
    ttl: float,
) -> dict:
    """Revoke one access token and register it in the token catalog."""

    _register(store, token_id, session, account, ACCESS, now, ttl)
    return _add(store, token_id, session, account, ACCESS, now + ttl)


def revoke_refresh(
    store: dict,
    token_id: str,
    session: str,
    account: str,
    now: float,
    ttl: float,
) -> dict:
    """Revoke one refresh token and register it in the token catalog."""

    _register(store, token_id, session, account, REFRESH, now, ttl)
    return _add(store, token_id, session, account, REFRESH, now + ttl)


def _active(record: dict, now: float) -> bool:
    expires_at = record.get("expires_at")
    if expires_at is None:
        # A record without an expiry is malformed but must keep denying until
        # cleanup prunes it; never treat it as an implicit grant.
        return True
    return expires_at > now


def is_revoked(store: dict, token_id: str, now: float) -> bool:
    """Return whether the given token id is currently revoked.

    Matching is exact: a revocation for ``at-7`` must not revoke ``at-70``.
    An expired revocation record no longer denies access.  Tokens registered
    in the catalog are also covered by session-wide and account-wide
    revocations, which is what makes a logout invalidate every credential of
    the session rather than only the one that was presented.
    """

    records = _records(store)
    for record in records:
        if not _active(record, now):
            continue
        marker = record.get("token_id")
        if marker is not None and marker == token_id:
            return True

    info = _catalog(store).get(token_id)
    if info is None:
        return False
    session = info.get("session")
    account = info.get("account")
    for record in records:
        if not _active(record, now):
            continue
        kind = record.get("kind")
        if kind == SESSION and session and record.get("session") == session:
            return True
        if kind == ACCOUNT and account and record.get("account") == account:
            return True
    return False


def revoke_session(store: dict, session: str, now: float) -> int:
    """Revoke every token that belongs to one session.

    Both access and refresh tokens are covered, and a session-wide record is
    written so the session stays revoked.  Returns the number of catalog
    tokens the revocation covered.
    """

    expires_at = now + DEFAULT_TTL
    count = 0
    for token_id, info in list(_catalog(store).items()):
        if info.get("session") != session:
            continue
        count += 1
        _add(
            store,
            token_id,
            session,
            info.get("account"),
            info.get("kind") or ACCESS,
            expires_at,
        )
    _add(store, None, session, None, SESSION, expires_at)
    return count


def revoke_account(store: dict, account: str, now: float) -> int:
    """Revoke every token that belongs to one account.

    Access and refresh tokens are both revoked; skipping either half would let
    the account keep refreshing after logout.  Returns the number of catalog
    tokens the revocation covered.
    """

    expires_at = now + DEFAULT_TTL
    count = 0
    for token_id, info in list(_catalog(store).items()):
        if info.get("account") != account:
            continue
        count += 1
        _add(
            store,
            token_id,
            info.get("session"),
            account,
            info.get("kind") or ACCESS,
            expires_at,
        )
    _add(store, None, None, account, ACCOUNT, expires_at)
    return count


def cleanup(store: dict, now: float) -> int:
    """Remove revocation records whose expiry has passed.

    Records that carry no expiry are malformed and pruned as well: otherwise
    they would accumulate without bound.
    """

    records = _records(store)
    kept = []
    removed = 0
    for record in records:
        expires_at = record.get("expires_at")
        if expires_at is None or expires_at <= now:
            removed += 1
        else:
            kept.append(record)
    records[:] = kept
    return removed


def query_revocations(
    store: dict,
    session: str | None = None,
    account: str | None = None,
    token_id: str | None = None,
    kind: str | None = None,
    now: float | None = None,
) -> list[dict]:
    """Return revocation records filtered by account and/or session.

    The revocation list has to be queryable along both the session and the
    account dimension; every filter is optional and filters are AND-ed.  When
    ``now`` is given, expired records are excluded so callers only see
    revocations that are still in force.  A fresh list is returned; the store
    is never modified here.
    """

    rows = list(store.get("revocations") or [])
    if session is not None:
        rows = [record for record in rows if record.get("session") == session]
    if account is not None:
        rows = [record for record in rows if record.get("account") == account]
    if token_id is not None:
        rows = [record for record in rows if record.get("token_id") == token_id]
    if kind is not None:
        rows = [record for record in rows if record.get("kind") == kind]
    if now is not None:
        rows = [record for record in rows if _active(record, now)]
    return rows


def revocations_by_session(
    store: dict, session: str, now: float | None = None
) -> list[dict]:
    """Return revocation records belonging to one session."""

    return query_revocations(store, session=session, now=now)


def revocations_by_account(
    store: dict, account: str, now: float | None = None
) -> list[dict]:
    """Return revocation records belonging to one account."""

    return query_revocations(store, account=account, now=now)


list_revocations = query_revocations
find_revocations = query_revocations


def validate_store(store: dict) -> list[str]:
    """Return a list of integrity problems found in the revocation records."""

    problems: list[str] = []
    seen: set[tuple] = set()
    for record in _records(store):
        token_id = record.get("token_id")
        session = record.get("session")
        if token_id is not None and not session:
            problems.append("missing session: %s" % (token_id,))
        if record.get("expires_at") is None:
            problems.append("missing expires_at: %s" % (token_id,))
        key = _key(record)
        if key in seen:
            problems.append("duplicate record: %s" % (token_id,))
        else:
            seen.add(key)
    return problems


def logout_batch(requests: list[dict], store: dict, now: float) -> dict:
    """Process a batch of logout requests, revoking each request's credentials.

    Each request uses its own session and account and is handled in isolation:
    a failure in one request never changes the outcome of another.
    """

    results: list[dict] = []
    for index, request in enumerate(requests):
        try:
            access_token = request["access_token"]
            account = request["account"]
            session = request.get("session")
            ttl = float(request.get("ttl", DEFAULT_TTL))
            revoke_access(store, access_token, session, account, now, ttl)
            refresh_token = request.get("refresh_token")
            if refresh_token:
                revoke_refresh(store, refresh_token, session, account, now, ttl)
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
