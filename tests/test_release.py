"""Release-state transitions and the documented entry point."""

from __future__ import annotations

import io
import os
import sqlite3
import subprocess
import sys
import tomllib
from contextlib import closing
from pathlib import Path
from typing import TYPE_CHECKING, Never, cast

import example
import pytest

import vault
from vault import ReleaseIdentity, ReleaseStateError, SQLiteReleaseState

if TYPE_CHECKING:
    from collections.abc import Mapping

ROOT = Path(__file__).resolve().parents[1]
FIRST = ReleaseIdentity(3, "a" * 64)
SECOND = ReleaseIdentity(4, "b" * 64)


@pytest.mark.parametrize(
    ("incoming", "expected", "message"),
    [
        (ReleaseIdentity(2, "a" * 64), FIRST, "older"),
        (FIRST, FIRST, None),
        (ReleaseIdentity(3, "b" * 64), FIRST, "conflicts"),
        (SECOND, SECOND, None),
    ],
)
def test_release_transaction(
    incoming: ReleaseIdentity,
    expected: ReleaseIdentity,
    message: str | None,
) -> None:
    prepared: list[ReleaseIdentity] = []

    with closing(sqlite3.connect(":memory:")) as connection:

        def prepare() -> None:
            assert connection.in_transaction
            prepared.append(incoming)

        state = SQLiteReleaseState(
            "ignored.db", "dispatch", allow_initial=True
        )
        with connection:
            state._accept(connection, FIRST)
        state = SQLiteReleaseState("ignored.db", "dispatch")
        if message is None:
            with connection:
                state._accept(connection, incoming, prepare=prepare)
        else:
            with pytest.raises(ReleaseStateError, match=message), connection:
                state._accept(connection, incoming, prepare=prepare)
        row = cast(
            "tuple[int, str] | None",
            connection.execute(
                "SELECT version, digest FROM accepted_releases "
                "WHERE namespace = ?",
                ("dispatch",),
            ).fetchone(),
        )
        assert row == (expected.version, expected.digest)
    assert prepared == ([incoming] if message is None else [])


def test_failed_first_preparation_allows_later_enrolment() -> None:
    def unavailable() -> Never:
        raise vault.BundleError("Cannot initialise fixture")

    with closing(sqlite3.connect(":memory:")) as connection:
        state = SQLiteReleaseState(
            "ignored.db", "dispatch", allow_initial=True
        )
        with pytest.raises(vault.BundleError, match="fixture"), connection:
            state._accept(connection, SECOND, prepare=unavailable)
        assert not connection.in_transaction
        with connection:
            state._accept(connection, FIRST)
        row = cast(
            "tuple[int] | None",
            connection.execute(
                "SELECT version FROM accepted_releases"
            ).fetchone(),
        )
        assert row == (FIRST.version,)


def test_admission_serialises_the_version_check_and_preparation() -> None:
    uri = "file:admission-tests?mode=memory&cache=shared"
    state = SQLiteReleaseState("ignored.db", "dispatch", allow_initial=True)

    def unexpected() -> Never:
        raise AssertionError("The competing release should not prepare")

    with (
        closing(sqlite3.connect(uri, uri=True)) as first,
        closing(sqlite3.connect(uri, uri=True)) as second,
    ):

        def while_writing() -> None:
            assert first.in_transaction
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                state._accept(second, FIRST, prepare=unexpected)

        with first:
            state._accept(first, SECOND, prepare=while_writing)
        with pytest.raises(ReleaseStateError, match="older"), second:
            state._accept(second, FIRST, prepare=unexpected)


def test_first_install_requires_explicit_enrolment() -> None:
    with pytest.raises(TypeError, match="allow_initial must be bool"):
        SQLiteReleaseState(
            "ignored.db", "dispatch", allow_initial=cast("bool", "false")
        )
    with closing(sqlite3.connect(":memory:")) as connection:
        state = SQLiteReleaseState("ignored.db", "dispatch")
        with (
            pytest.raises(ReleaseStateError, match="No enrolled release"),
            connection,
        ):
            state._accept(connection, FIRST)


def test_invalid_stored_identity_blocks_admission() -> None:
    with closing(sqlite3.connect(":memory:")) as connection:
        state = SQLiteReleaseState(
            "ignored.db", "dispatch", allow_initial=True
        )
        with connection:
            state._accept(connection, FIRST)
        with connection:
            connection.execute(
                "UPDATE accepted_releases SET version = ? WHERE namespace = ?",
                ("invalid", "dispatch"),
            )
        with (
            pytest.raises(ReleaseStateError, match="Invalid stored"),
            connection,
        ):
            state._accept(connection, SECOND)


def test_state_namespaces_have_independent_versions() -> None:
    with closing(sqlite3.connect(":memory:")) as connection:
        with connection:
            SQLiteReleaseState("ignored.db", "a", allow_initial=True)._accept(
                connection, SECOND
            )
        with connection:
            SQLiteReleaseState("ignored.db", "b", allow_initial=True)._accept(
                connection, FIRST
            )
        rows = cast(
            "list[tuple[str, int]]",
            connection.execute(
                "SELECT namespace, version FROM accepted_releases "
                "ORDER BY namespace",
            ).fetchall(),
        )
        assert rows == [("a", 4), ("b", 3)]


def test_failed_state_access_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(_uri: str, *, uri: bool) -> Never:
        assert uri
        raise sqlite3.OperationalError("fixture")

    monkeypatch.setattr(sqlite3, "connect", unavailable)
    with pytest.raises(ReleaseStateError, match="Cannot access") as captured:
        SQLiteReleaseState("ignored.db", "dispatch").accept(FIRST)
    assert isinstance(captured.value.__cause__, sqlite3.OperationalError)


def test_candidate_version_and_dependency_agree() -> None:
    parsed = cast(
        "dict[str, object]",
        tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8")),
    )
    project = cast("dict[str, object]", parsed["project"])
    assert project["version"] == "0.3.0"
    assert project["dependencies"] == [
        (ROOT / "requirements.txt").read_text().strip()
    ]
    assert project["requires-python"] == ">=3.12"


@pytest.mark.parametrize("readme", ["README.md", "README.ru.md"])
def test_both_guides_point_to_runnable_cli(readme: str) -> None:
    instruction = "PYTHONPATH=src python examples/example.py --output demo-run"
    assert instruction in (ROOT / readme).read_text(encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-B", "examples/example.py", "--help"],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": "src"},
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "--output" in result.stdout


def test_demo_refuses_existing_output() -> None:
    with pytest.raises(FileExistsError, match=r"exists"):
        example.run_demo(ROOT)


def test_demo_runs_end_to_end_on_in_memory_io(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    published: dict[str, bytes] = {}

    def capture(
        path: vault.PathInput,
        encrypted: Mapping[str, str],
        meta: vault.BundleMetadata,
        _limits: vault.BundleLimits,
    ) -> None:
        published[os.fspath(path)] = "".join(
            vault._bundle_lines(encrypted, meta)
        ).encode()

    def open_fixture(
        path: str,
        _mode: str,
        **_kwargs: object,
    ) -> io.BytesIO:
        return io.BytesIO(published[path])

    class SharedConnection(sqlite3.Connection):
        def close(self) -> None:
            return None

    original = sqlite3.connect
    with closing(original(":memory:", factory=SharedConnection)) as connection:

        def connect(*_args: object, **_kwargs: object) -> SharedConnection:
            return connection

        def mkdir(*_args: object, **_kwargs: object) -> None:
            return None

        monkeypatch.setattr(vault, "_write_bundle_module", capture)
        monkeypatch.setattr(vault, "open", open_fixture, raising=False)
        monkeypatch.setattr(Path, "mkdir", mkdir)
        monkeypatch.setattr(sqlite3, "connect", connect)
        try:
            example.run_demo(Path("fixture"))
        finally:
            sqlite3.Connection.close(connection)

    text = capsys.readouterr().out
    assert text.count("OK -- 4/4") == 2
    assert "3 rolled back" in text
    assert "wrong key was rejected" in text
    assert "older release was rejected" in text
    current = vault._LiteralBundle(
        published["fixture/current.py"].decode(),
        vault.DEFAULT_LIMITS,
    ).parse()[1]
    older = vault._LiteralBundle(
        published["fixture/previous.py"].decode(),
        vault.DEFAULT_LIMITS,
    ).parse()[1]
    assert current["version"] == 3
    assert older["version"] == 2
