"""Unit tests for custom_napalm.mikrotik_routeros.ROSDriver."""

from pathlib import Path

from custom_napalm.mikrotik_routeros import ROSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestROSDriver(BaseDriverTest):
    """Unit tests for ROSDriver using file-based CLI mocks."""

    driver_cls = ROSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"


def test_ros_type_to_netbox_mapping():
    """RouterOS interface types map to NetBox types; physical/unknown stay unset."""
    from custom_napalm.mikrotik_routeros import _ros_type_to_netbox

    assert _ros_type_to_netbox("bond") == "lag"
    assert _ros_type_to_netbox("vlan") == "virtual"
    assert _ros_type_to_netbox("bridge") == "bridge"
    assert _ros_type_to_netbox("gre-tunnel") == "virtual"
    assert _ros_type_to_netbox("VLAN") == "virtual"  # case-insensitive
    # physical / wireless / unknown -> unset (fall through to existing logic)
    assert _ros_type_to_netbox("ether") is None
    assert _ros_type_to_netbox("wlan") is None
    assert _ros_type_to_netbox("") is None


def test_get_interfaces_ip_never_raises(caplog):
    """
    A parse failure costs the addresses, not the device.

    The runner calls get_interfaces_ip outside any handler of its own, so an
    exception escaping it fails the whole run for that device and loses its
    interfaces, VLANs and config as well. It must return empty instead, and
    say so at warning level: silence is what made the RouterOS 7 column change
    present as a successful run with no addresses.
    """
    import logging

    from custom_napalm.mikrotik_routeros import ROSDriver

    class _ExplodingDevice:
        @staticmethod
        def send_command(_cmd):
            return object()  # not str: blows up in the parser

    driver = object.__new__(ROSDriver)
    driver.device = _ExplodingDevice()

    with caplog.at_level(logging.WARNING):
        assert driver.get_interfaces_ip() == {}
    assert any(
        "ip address print" in r.message and r.levelno >= logging.WARNING
        for r in caplog.records
    )


def test_get_interfaces_ip_warns_when_the_device_returns_nothing(caplog):
    """An empty response is a reportable condition, not an empty device."""
    import logging

    from custom_napalm.mikrotik_routeros import ROSDriver

    class _SilentDevice:
        @staticmethod
        def send_command(_cmd):
            return ""

    driver = object.__new__(ROSDriver)
    driver.device = _SilentDevice()

    with caplog.at_level(logging.WARNING):
        assert driver.get_interfaces_ip() == {}
    assert any("returned no output" in r.message for r in caplog.records)


def _driver_with_output(text):
    from custom_napalm.mikrotik_routeros import ROSDriver

    class _Device:
        @staticmethod
        def send_command(_cmd):
            return text

    driver = object.__new__(ROSDriver)
    driver.device = _Device()
    return driver


def test_no_addresses_is_not_reported_as_a_format_change(caplog):
    """
    A device with nothing to report is ordinary, not a problem.

    An L2-only switch, or one whose every address is disabled or invalid,
    yields no addresses. Warning there would put the line in every poll of a
    healthy device and teach operators to scroll past the one poll where it
    means something.
    """
    import logging

    empty = "Flags: X - disabled, I - invalid, D - dynamic\n# ADDRESS NETWORK INTERFACE\n"
    all_inactive = (
        "Flags: X - disabled, I - invalid\n"
        "# ADDRESS        NETWORK      INTERFACE\n"
        "0 X 192.0.2.1/24   192.0.2.0    ether1\n"
        "1 I 198.51.100.1/24 198.51.100.0 ether2\n"
    )
    for output in (empty, all_inactive):
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            assert _driver_with_output(output).get_interfaces_ip() == {}
        assert not [r for r in caplog.records if "format may have changed" in r.message]


def test_unreadable_address_rows_are_reported(caplog):
    """Address-shaped lines that match no row format are worth a warning."""
    import logging

    unreadable = (
        "Flags: X - disabled\n"
        "# ADDRESS NETWORK INTERFACE\n"
        "somethingnew 192.0.2.1/24 192.0.2.0\n"
    )
    with caplog.at_level(logging.WARNING):
        assert _driver_with_output(unreadable).get_interfaces_ip() == {}
    assert any("format may have changed" in r.message for r in caplog.records)


def test_column_padding_keeps_names_containing_spaces_intact():
    """A single space inside a name is not a column separator."""
    spaced_vrf = (
        "Columns: ADDRESS, NETWORK, INTERFACE, VRF\n"
        "# ADDRESS        NETWORK      INTERFACE   VRF\n"
        "0  192.0.2.1/24   192.0.2.0    ether1      customer blue\n"
    )
    assert _driver_with_output(spaced_vrf).get_interfaces_ip() == {
        "ether1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}
    }

    spaced_interface = (
        "Columns: ADDRESS, NETWORK, INTERFACE, VRF\n"
        "# ADDRESS        NETWORK      INTERFACE        VRF\n"
        "0  192.0.2.1/24   192.0.2.0    ether1 customer  main\n"
    )
    assert _driver_with_output(spaced_interface).get_interfaces_ip() == {
        "ether1 customer": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}
    }


def test_flags_survive_a_comment_line_before_the_address():
    """
    A line between the index line and its address must not take the flags.

    RouterOS prints a commented address over two lines, and can print further
    comment lines between them. Losing the flags there reports a disabled or
    invalid address as active, which is the SSH and SNMP disagreement the flag
    filtering exists to prevent.
    """
    output = (
        "Flags: X - disabled, I - invalid\n"
        "# ADDRESS        NETWORK      INTERFACE\n"
        "0 X ;;; disabled address\n"
        ";;; second comment line\n"
        "    192.0.2.1/24   192.0.2.0    ether1\n"
        "1 I ;;; invalid one\n"
        ";;; and a note\n"
        "    198.51.100.1/24 198.51.100.0 ether2\n"
        "2   203.0.113.1/24  203.0.113.0  ether3\n"
    )
    assert _driver_with_output(output).get_interfaces_ip() == {
        "ether3": {"ipv4": {"203.0.113.1": {"prefix_length": 24}}}
    }


def test_partial_reads_are_reported(caplog):
    """
    An unreadable row is worth saying so even when others were read.

    A device printing one row in a format we know and another in one we do not
    returns plausible partial data, which is harder to notice than returning
    nothing at all.
    """
    import logging

    mixed = (
        "Flags: X - disabled\n"
        "# ADDRESS        NETWORK      INTERFACE\n"
        "0  192.0.2.1/24   192.0.2.0    ether1\n"
        "somethingnew 198.51.100.1/24 198.51.100.0\n"
    )
    with caplog.at_level(logging.WARNING):
        result = _driver_with_output(mixed).get_interfaces_ip()
    assert result == {"ether1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}
    assert any("matched no known row format" in r.message for r in caplog.records)


def test_interface_names_broken_up_by_column_padding():
    """
    An interface name spaced like column padding is recovered where it can be.

    The name is kept exactly as the device printed it, in both layouts.
    get_interfaces reads names from a quoted field and keeps them verbatim,
    so collapsing the spacing here would key the address to an interface that
    does not exist and orphan it.
    """
    no_vrf = (
        "Columns: ADDRESS, NETWORK, INTERFACE\n"
        "# ADDRESS        NETWORK      INTERFACE\n"
        "0  192.0.2.1/24   192.0.2.0    ether1  customer\n"
    )
    assert _driver_with_output(no_vrf).get_interfaces_ip() == {
        "ether1  customer": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}
    }

    with_vrf = (
        "Columns: ADDRESS, NETWORK, INTERFACE, VRF\n"
        "# ADDRESS        NETWORK      INTERFACE          VRF\n"
        "0  192.0.2.1/24   192.0.2.0    ether1  customer   main\n"
    )
    assert _driver_with_output(with_vrf).get_interfaces_ip() == {
        "ether1  customer": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}
    }


def test_a_row_whose_columns_cannot_be_read_is_reported(caplog):
    """
    A recognised address whose columns are unreadable is not silently dropped.

    A VRF column cut off by terminal width leaves a row that matches as an
    address but cannot say where the address lives. Dropping it quietly is the
    partial-data failure the unread count exists to catch.
    """
    import logging

    truncated = (
        "Columns: ADDRESS, NETWORK, INTERFACE, VRF\n"
        "# ADDRESS        NETWORK      INTERFACE   VRF\n"
        "0  192.0.2.1/24   192.0.2.0\n"
        "1  198.51.100.1/24 198.51.100.0 ether2      main\n"
    )
    with caplog.at_level(logging.WARNING):
        result = _driver_with_output(truncated).get_interfaces_ip()
    assert result == {"ether2": {"ipv4": {"198.51.100.1": {"prefix_length": 24}}}}
    assert any("matched no known row format" in r.message for r in caplog.records)


def test_column_boundaries_come_from_the_header():
    """
    The header's column offsets settle what padding alone cannot.

    Two spaces inside a name and two between columns are the same two spaces,
    so any rule based on runs of whitespace lets one column swallow the
    other's value. The header gives the real boundaries, and the row's own
    address position gives the shift, since the header omits the flags field.
    """
    header = (
        "Columns: ADDRESS, NETWORK, INTERFACE, VRF\n"
        "# ADDRESS        NETWORK      INTERFACE          VRF\n"
    )
    # A VRF name spaced like padding.
    spaced_vrf = header + "0  192.0.2.1/24   192.0.2.0    ether1             customer  blue\n"
    assert _driver_with_output(spaced_vrf).get_interfaces_ip() == {
        "ether1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}
    }
    # An interface name spaced like padding.
    spaced_intf = header + "0  192.0.2.1/24   192.0.2.0    ether1  customer   main\n"
    assert _driver_with_output(spaced_intf).get_interfaces_ip() == {
        "ether1  customer": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}
    }
    # Both at once, which no whitespace rule can separate.
    both = header + "0  192.0.2.1/24   192.0.2.0    ether1  customer   cust  blue\n"
    assert _driver_with_output(both).get_interfaces_ip() == {
        "ether1  customer": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}
    }
    # A flags letter shifts the row; the offset is measured per row, not fixed.
    flagged = (
        "Flags: D - dynamic\n"
        + header
        + "0 D 192.0.2.1/24   192.0.2.0    ether1             main\n"
    )
    assert _driver_with_output(flagged).get_interfaces_ip() == {
        "ether1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}
    }
