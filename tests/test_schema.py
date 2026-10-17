"""Tests for core.schema (Security Baseline Model). Owner: P1."""

from core.schema import (
    Authentication,
    Banner,
    Crypto,
    DeviceCategory,
    FieldValue,
    Logging,
    Management,
    SecurityBaseline,
    Snmp,
    Time,
    is_valid_path,
    rule_paths,
    set_field,
    valid_paths,
    get_field,
)


def test_default_baseline_is_all_null():
    b = SecurityBaseline()
    assert b.management.telnet_enabled.value is None
    assert b.management.ssh_enabled.value is None
    assert b.authentication.password_min_length.value is None
    assert b.banner.login_banner_set.value is None


def test_field_value_carry_evidence():
    fv = FieldValue(
        value=True,
        source_line="ip ssh version 2",
        line_number=14,
        confidence=0.93,
        origin="mapping",
    )
    assert fv.value is True
    assert fv.source_line == "ip ssh version 2"
    assert fv.line_number == 14
    assert fv.confidence == 0.93
    assert fv.origin == "mapping"


def test_null_not_conflated_with_false():
    b = SecurityBaseline()
    assert b.management.telnet_enabled.value is None  # unknown
    b.management.telnet_enabled.value = False  # explicitly disabled
    assert b.management.telnet_enabled.value is False


def test_all_categories_present():
    b = SecurityBaseline()
    assert isinstance(b.device, DeviceCategory)
    assert isinstance(b.management, Management)
    assert isinstance(b.authentication, Authentication)
    assert isinstance(b.logging, Logging)
    assert isinstance(b.snmp, Snmp)
    assert isinstance(b.time, Time)
    assert isinstance(b.crypto, Crypto)
    assert isinstance(b.banner, Banner)


def test_valid_paths_returns_all_field_value_leaves():
    paths = valid_paths()
    expected = {
        "device.vendor",
        "device.os",
        "device.hostname",
        "device.serial",
        "management.telnet_enabled",
        "management.ssh_enabled",
        "management.ssh_version",
        "management.http_server_enabled",
        "management.https_enabled",
        "management.idle_timeout_min",
        "authentication.password_min_length",
        "authentication.password_encryption",
        "authentication.aaa_enabled",
        "logging.syslog_servers",
        "logging.admin_logging",
        "snmp.v1_v2_enabled",
        "snmp.default_community",
        "time.ntp_servers",
        "crypto.weak_ciphers_enabled",
        "banner.login_banner_set",
    }
    assert paths == expected
    assert len(paths) == 20


def test_is_valid_path():
    assert is_valid_path("management.telnet_enabled") is True
    assert is_valid_path("device.serial") is True
    assert is_valid_path("management.nope") is False
    assert is_valid_path("device") is False
    assert is_valid_path("") is False


def test_set_field_sets_value_and_evidence():
    b = SecurityBaseline()
    set_field(
        b,
        "management.ssh_version",
        2,
        source_line="ip ssh version 2",
        line_number=7,
        confidence=0.93,
        origin="mapping",
    )
    fv = b.management.ssh_version
    assert fv.value == 2
    assert fv.source_line == "ip ssh version 2"
    assert fv.line_number == 7
    assert fv.confidence == 0.93
    assert fv.origin == "mapping"


def test_set_field_invalid_path_raises():
    b = SecurityBaseline()
    try:
        set_field(
            b,
            "management.nope",
            True,
            source_line="x",
            line_number=1,
            confidence=0.5,
            origin="llm",
        )
    except ValueError as e:
        assert "Invalid schema path" in str(e)
    else:
        raise AssertionError("expected ValueError for invalid path")


def test_set_field_type_mismatch_raises():
    b = SecurityBaseline()
    try:
        set_field(
            b,
            "management.ssh_version",
            "two",
            source_line="x",
            line_number=1,
            confidence=0.5,
            origin="llm",
        )
    except ValueError as e:
        assert "expects int" in str(e)
    else:
        raise AssertionError("expected ValueError for type mismatch")


def test_set_field_bool_not_accepted_as_int():
    b = SecurityBaseline()
    try:
        set_field(
            b,
            "management.idle_timeout_min",
            True,
            source_line="x",
            line_number=1,
            confidence=0.5,
            origin="llm",
        )
    except ValueError as e:
        assert "expects int" in str(e)
    else:
        raise AssertionError("expected ValueError for bool-as-int")


def test_set_field_none_always_allowed():
    b = SecurityBaseline()
    set_field(
        b,
        "management.ssh_version",
        None,
        source_line="",
        line_number=None,
        confidence=0.0,
        origin="llm",
    )
    assert b.management.ssh_version.value is None


def test_set_field_list_str_valid():
    b = SecurityBaseline()
    set_field(
        b,
        "logging.syslog_servers",
        ["10.0.0.5"],
        source_line="logging host 10.0.0.5",
        line_number=17,
        confidence=0.9,
        origin="mapping",
    )
    assert b.logging.syslog_servers.value == ["10.0.0.5"]


def test_set_field_list_str_nonstr_elements_raise():
    b = SecurityBaseline()
    try:
        set_field(
            b,
            "time.ntp_servers",
            [1, 2],
            source_line="x",
            line_number=1,
            confidence=0.5,
            origin="llm",
        )
    except ValueError as e:
        assert "expects list[str]" in str(e)
    else:
        raise AssertionError("expected ValueError for non-str list")


def test_set_field_value_without_source_line_raises():
    b = SecurityBaseline()
    try:
        set_field(
            b,
            "management.telnet_enabled",
            False,
            source_line="",
            line_number=1,
            confidence=0.5,
            origin="llm",
        )
    except ValueError as e:
        assert "source_line is required" in str(e)
    else:
        raise AssertionError("expected ValueError for missing source_line")


def test_rule_paths_excludes_device():
    paths = rule_paths()
    assert "device.vendor" not in paths
    assert "device.os" not in paths
    assert "device.hostname" not in paths
    assert "device.serial" not in paths
    assert "management.telnet_enabled" in paths
    assert "snmp.default_community" in paths
    assert len(paths) == len(valid_paths()) - 4


def test_get_field_returns_fieldvalue():
    b = SecurityBaseline()
    set_field(
        b,
        "management.ssh_version",
        2,
        source_line="ip ssh version 2",
        line_number=7,
        confidence=0.93,
        origin="mapping",
    )
    fv = get_field(b, "management.ssh_version")
    assert fv.value == 2
    assert fv.source_line == "ip ssh version 2"


def test_get_field_invalid_path_raises():
    b = SecurityBaseline()
    try:
        get_field(b, "management.nope")
    except ValueError as e:
        assert "Invalid schema path" in str(e)
    else:
        raise AssertionError("expected ValueError for invalid path")
