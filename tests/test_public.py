"""Public acceptance tests for logout revocation."""

from __future__ import annotations

from logoutrev import (
    cleanup,
    is_revoked,
    logout_batch,
    revoke_access,
    revoke_refresh,
)

NOW = 1_700_000_000.0


def test_revoke_access_token() -> None:
    store: dict = {}

    record = revoke_access(store, "at-1", "session-1", "account-1", NOW, 60)

    assert is_revoked(store, "at-1", NOW) is True
    assert record["kind"] == "access"
    assert record["session"] == "session-1"
    assert record["expires_at"] == NOW + 60


def test_revoke_refresh_token() -> None:
    store: dict = {}

    record = revoke_refresh(store, "rt-1", "session-1", "account-1", NOW, 90)

    assert is_revoked(store, "rt-1", NOW) is True
    assert record["kind"] == "refresh"
    assert record["expires_at"] == NOW + 90


def test_revocation_decision_is_exact() -> None:
    store: dict = {}

    revoke_access(store, "at-7", "session-1", "account-1", NOW, 60)

    assert is_revoked(store, "at-7", NOW) is True
    assert is_revoked(store, "at-70", NOW) is False


def test_cleanup_removes_only_expired_records() -> None:
    store = {
        "revocations": [
            {
                "token_id": "at-old",
                "session": "session-1",
                "account": "account-1",
                "kind": "access",
                "expires_at": NOW - 10,
            },
            {
                "token_id": "at-new",
                "session": "session-1",
                "account": "account-1",
                "kind": "access",
                "expires_at": NOW + 10,
            },
        ]
    }

    removed = cleanup(store, NOW)

    assert removed == 1
    assert [record["token_id"] for record in store["revocations"]] == ["at-new"]


def test_logout_batch_keeps_requests_independent() -> None:
    store: dict = {}
    requests = [
        {
            "access_token": "at-1",
            "refresh_token": "rt-1",
            "session": "session-1",
            "account": "account-1",
            "ttl": 60,
        },
        {
            "access_token": "at-2",
            "refresh_token": "rt-2",
            "session": "session-2",
            "account": "account-2",
            "ttl": 60,
        },
    ]

    result = logout_batch(requests, store, NOW)

    assert result["ok"] == 2
    assert result["failed"] == 0
    assert is_revoked(store, "at-2", NOW) is True
    assert is_revoked(store, "rt-2", NOW) is True
    records = {record["token_id"]: record for record in store["revocations"]}
    assert records["at-2"]["session"] == "session-2"