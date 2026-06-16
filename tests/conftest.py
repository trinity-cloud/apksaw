"""Shared test fixtures for apksaw tests."""

import hashlib
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Helpers for building mock Androguard-like objects
# ---------------------------------------------------------------------------


def _make_string_analysis(value: str, xrefs=None):
    """Build a mock StringAnalysis object."""
    sa = MagicMock()
    sa.get_value.return_value = value
    # get_xref_from returns list of (class_analysis, method_analysis) tuples
    xref_list = xrefs or []
    sa.get_xref_from.return_value = xref_list
    return sa


def _make_method_analysis(name: str, descriptor: str = "()V", access: str = "public", is_external: bool = False):
    """Build a mock MethodAnalysis object."""
    ma = MagicMock()
    ma.name = name
    ma.descriptor = descriptor
    ma.access = access
    ma.is_external.return_value = is_external
    # get_method() returns an encoded method mock
    em = MagicMock()
    code = MagicMock()
    bc = MagicMock()
    bc.get_instructions.return_value = []
    code.get_bc.return_value = bc
    em.get_code.return_value = code
    ma.get_method.return_value = em
    ma.get_xref_from.return_value = []
    return ma


def _make_field_analysis(name: str, field_type: str = "Ljava/lang/String;", access: str = "private"):
    """Build a mock FieldAnalysis object."""
    fa = MagicMock()
    fa.name = name
    field_obj = MagicMock()
    field_obj.get_descriptor.return_value = field_type
    field_obj.get_access_flags_string.return_value = access
    fa.get_field.return_value = field_obj
    return fa


def _make_class_analysis(
    dalvik_name: str,
    methods=None,
    fields=None,
    is_external: bool = False,
    superclass: str = "Ljava/lang/Object;",
    interfaces=None,
    access_flags: str = "public",
):
    """Build a mock ClassAnalysis object."""
    ca = MagicMock()
    ca.name = dalvik_name
    ca.is_external.return_value = is_external

    method_list = methods or []
    ca.get_methods.return_value = iter(method_list)

    field_list = fields or []
    ca.get_fields.return_value = iter(field_list)

    # vm_class (only meaningful for non-external)
    vm_class = MagicMock()
    vm_class.get_superclassname.return_value = superclass
    vm_class.get_interfaces.return_value = interfaces or []
    vm_class.get_access_flags_string.return_value = access_flags
    ca.get_vm_class.return_value = vm_class

    return ca


def _make_apk_mock():
    """Build a mock Androguard APK object with sensible defaults."""
    apk = MagicMock()
    apk.get_package.return_value = "com.example.testapp"
    apk.get_androidversion_name.return_value = "1.0.0"
    apk.get_androidversion_code.return_value = "1"
    apk.get_min_sdk_version.return_value = "21"
    apk.get_target_sdk_version.return_value = "33"
    apk.get_max_sdk_version.return_value = None
    apk.get_main_activity.return_value = "com.example.testapp.MainActivity"
    apk.get_permissions.return_value = [
        "android.permission.INTERNET",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
    ]
    apk.get_declared_permissions_details.return_value = {}

    # Build a minimal manifest XML stub using lxml
    try:
        from lxml import etree

        NS = "http://schemas.android.com/apk/res/android"
        manifest = etree.Element("manifest")
        manifest.set("package", "com.example.testapp")

        uses_perm = etree.SubElement(manifest, "uses-permission")
        uses_perm.set(f"{{{NS}}}name", "android.permission.INTERNET")

        app = etree.SubElement(manifest, "application")
        app.set(f"{{{NS}}}allowBackup", "false")
        app.set(f"{{{NS}}}debuggable", "false")

        activity = etree.SubElement(app, "activity")
        activity.set(f"{{{NS}}}name", "com.example.testapp.MainActivity")
        activity.set(f"{{{NS}}}exported", "true")

        intent_filter = etree.SubElement(activity, "intent-filter")
        action = etree.SubElement(intent_filter, "action")
        action.set(f"{{{NS}}}name", "android.intent.action.MAIN")
        category = etree.SubElement(intent_filter, "category")
        category.set(f"{{{NS}}}name", "android.intent.category.LAUNCHER")

        apk.get_android_manifest_xml.return_value = manifest
    except ImportError:
        apk.get_android_manifest_xml.return_value = MagicMock()

    apk.get_activities.return_value = ["com.example.testapp.MainActivity"]
    apk.get_services.return_value = []
    apk.get_receivers.return_value = []
    apk.get_providers.return_value = []
    apk.get_files.return_value = [
        "AndroidManifest.xml",
        "classes.dex",
        "res/layout/activity_main.xml",
        "assets/config.json",
        "lib/arm64-v8a/libnative.so",
    ]
    apk.get_file.return_value = b"fake content"

    return apk


def _make_analysis_mock(classes=None, strings=None):
    """Build a mock Androguard Analysis object."""
    analysis = MagicMock()

    class_list = classes or []
    analysis.get_classes.return_value = iter(class_list)

    # find_classes: return classes whose name matches
    def _find_classes(name="", **kwargs):
        import re as _re
        for ca in class_list:
            try:
                if _re.search(name, ca.name):
                    yield ca
            except Exception:
                pass

    analysis.find_classes.side_effect = _find_classes

    string_list = strings or []
    analysis.get_strings.return_value = iter(string_list)

    def _find_strings(string="", **kwargs):
        import re as _re
        for sa in string_list:
            try:
                if _re.search(string, sa.get_value()):
                    yield sa
            except Exception:
                pass

    analysis.find_strings.side_effect = _find_strings

    def _get_methods():
        for ca in class_list:
            yield from ca.get_methods()

    analysis.get_methods.side_effect = _get_methods

    def _find_methods(classname="", methodname="", **kwargs):
        import re as _re
        for ca in class_list:
            try:
                if not _re.search(classname, ca.name):
                    continue
            except Exception:
                continue
            for ma in ca.get_methods():
                try:
                    if _re.search(methodname, ma.name):
                        yield ma
                except Exception:
                    pass

    analysis.find_methods.side_effect = _find_methods

    return analysis


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_apk_path(tmp_path):
    """Path to a temporary fake APK file (not a real APK, just a file on disk)."""
    fake_apk = tmp_path / "test.apk"
    # Write some bytes so the file exists and has a deterministic SHA256
    fake_apk.write_bytes(b"PK\x03\x04" + b"\x00" * 256)
    return fake_apk


@pytest.fixture
def mock_session(sample_apk_path):
    """
    A fully mocked Session object with realistic Androguard-like internals.

    The session's .apk, .analysis, and .dex_list properties all return
    pre-built mocks.  The session_id is fixed to "testsession01" so tests
    that look it up by ID can do so predictably.
    """
    # Build component mocks
    method_on_create = _make_method_analysis("onCreate", "(Landroid/os/Bundle;)V")
    method_on_start = _make_method_analysis("onStart", "()V")
    field_tag = _make_field_analysis("TAG", "Ljava/lang/String;", "private static final")

    main_activity_class = _make_class_analysis(
        dalvik_name="Lcom/example/testapp/MainActivity;",
        methods=[method_on_create, method_on_start],
        fields=[field_tag],
        superclass="Landroid/app/Activity;",
    )

    helper_class = _make_class_analysis(
        dalvik_name="Lcom/example/testapp/Helper;",
        methods=[_make_method_analysis("doSomething", "()Ljava/lang/String;")],
    )

    strings = [
        _make_string_analysis("https://api.example.com/v1/data"),
        _make_string_analysis("http://insecure.example.com/upload"),
        _make_string_analysis("AIzaSyABC123XYZ456abc789def012ghi345jkl"),  # fake Google API key pattern
        _make_string_analysis("/data/data/com.example.testapp/databases/app.db"),
        _make_string_analysis("SELECT * FROM users WHERE id = ?"),
        _make_string_analysis("android.permission.INTERNET"),
    ]

    apk_mock = _make_apk_mock()
    analysis_mock = _make_analysis_mock(
        classes=[main_activity_class, helper_class],
        strings=strings,
    )
    dex_mock = MagicMock()

    sha256 = hashlib.sha256(sample_apk_path.read_bytes()).hexdigest()

    session = MagicMock()
    session.session_id = "testsession01"
    session.apk_path = sample_apk_path
    session.sha256 = sha256
    session.package_name = "com.example.testapp"
    session.workspace = sample_apk_path.parent / "workspace"
    session.workspace.mkdir(exist_ok=True)

    # Make property access return the mocks directly (not trigger get_androguard)
    type(session).apk = property(lambda self: apk_mock)
    type(session).analysis = property(lambda self: analysis_mock)
    type(session).dex_list = property(lambda self: dex_mock)
    session.get_androguard.return_value = (apk_mock, dex_mock, analysis_mock)

    return session
