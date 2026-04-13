"""Tests for DEX bytecode analysis and decompilation tools."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import _make_class_analysis, _make_method_analysis

# Pre-import tool functions at collection time (conftest.py stubs mcp/androguard)
from apksaw.tools.dex import list_classes, decompile_method


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _inject_session(mock_session):
    return patch("apksaw.tools.dex.get_session", return_value=mock_session)


# ---------------------------------------------------------------------------
# list_classes
# ---------------------------------------------------------------------------


def test_list_classes_returns_non_external(mock_session):
    """list_classes excludes external classes by default."""
    external_class = _make_class_analysis(
        dalvik_name="Landroid/app/Activity;",
        is_external=True,
    )
    mock_session.analysis.get_classes.return_value = iter([
        _make_class_analysis("Lcom/example/testapp/MainActivity;"),
        _make_class_analysis("Lcom/example/testapp/Helper;"),
        external_class,
    ])

    with _inject_session(mock_session):
        result = list_classes(mock_session.session_id, exclude_external=True)

    assert result["status"] == "ok"
    names = [c["class_name"] for c in result["data"]["classes"]]
    assert "com.example.testapp.MainActivity" in names
    assert "android.app.Activity" not in names


def test_list_classes_filter_by_package(mock_session):
    """list_classes respects the package_filter argument."""
    mock_session.analysis.get_classes.return_value = iter([
        _make_class_analysis("Lcom/example/testapp/MainActivity;"),
        _make_class_analysis("Lcom/other/SomeClass;"),
    ])

    with _inject_session(mock_session):
        result = list_classes(mock_session.session_id, package_filter="com.example.testapp")

    assert result["status"] == "ok"
    names = [c["class_name"] for c in result["data"]["classes"]]
    assert all(n.startswith("com.example.testapp") for n in names)
    assert "com.other.SomeClass" not in names


def test_list_classes_pagination(mock_session):
    """list_classes respects limit and offset for pagination."""
    classes = [_make_class_analysis(f"Lcom/example/Class{i};") for i in range(10)]
    mock_session.analysis.get_classes.return_value = iter(classes)

    with _inject_session(mock_session):
        result = list_classes(mock_session.session_id, limit=3, offset=2)

    data = result["data"]
    assert data["total"] == 10
    assert len(data["classes"]) == 3
    assert data["offset"] == 2
    assert data["limit"] == 3


def test_list_classes_bad_session():
    """list_classes returns status=error for an unknown session."""
    with patch("apksaw.tools.dex.get_session", side_effect=KeyError("Session not found")):
        result = list_classes("badid")

    assert result["status"] == "error"


# ---------------------------------------------------------------------------
# decompile_method
# ---------------------------------------------------------------------------


def test_decompile_method_class_not_found(mock_session):
    """decompile_method returns error when the class does not exist."""
    mock_session.analysis.find_classes.side_effect = lambda name="", **kw: iter([])

    with _inject_session(mock_session):
        result = decompile_method(
            mock_session.session_id,
            class_name="com.example.NoSuchClass",
            method_name="doThing",
        )

    assert result["status"] == "error"
    assert "not found" in result["data"]["message"].lower()


def test_decompile_method_returns_smali_fallback(mock_session):
    """decompile_method returns smali disassembly when DAD decompilation fails."""
    main_class = _make_class_analysis(
        dalvik_name="Lcom/example/testapp/MainActivity;",
        methods=[_make_method_analysis("onCreate", "(Landroid/os/Bundle;)V")],
    )
    mock_session.analysis.find_classes.side_effect = lambda name="", **kw: iter([main_class])
    # dex_list is a property on the mock type — read it via the session's existing mock
    # (the property already returns a MagicMock from the fixture)

    with _inject_session(mock_session):
        result = decompile_method(
            mock_session.session_id,
            class_name="com.example.testapp.MainActivity",
            method_name="onCreate",
        )

    assert result["status"] == "ok"
    assert len(result["data"]["results"]) >= 1
    first = result["data"]["results"][0]
    assert "source" in first
    assert first["language"] in ("smali", "java")
