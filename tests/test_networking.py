import socket

import hypothesis.strategies as st
import pytest
from hypothesis import given
from port_scanner.networking import arp_scan, is_ip_address, is_port_open, ping, tcp_syn_scan
from scapy.all import TCP  # type: ignore


@given(st.lists(st.integers(min_value=0, max_value=255), min_size=4, max_size=4))  # make a list of 4 numbers from 0-255
def test_is_ip_address_with_valid_addresses(numbers):
    address = ".".join(map(str, numbers))  # make ip address
    assert is_ip_address(address)


@given(
    st.lists(
        st.integers(min_value=-100000, max_value=-1) | st.integers(min_value=256, max_value=100000),
        min_size=4,
        max_size=4,
    )
)
def test_is_ip_address_with_non_valid_octets(numbers):
    address = ".".join(map(str, numbers))  # make non valid ip address
    assert not is_ip_address(address)


@given(st.one_of(st.none(), st.booleans(), st.integers(), st.floats(), st.lists(st.booleans())))
def test_is_ip_address_with_wrong_type(address):
    assert not is_ip_address(address)


def test_ping_localhost():
    assert ping("127.0.0.1")


def test_ping_invalid_ip_raises_value_error():
    with pytest.raises(ValueError):
        assert ping("255.256.0.0")


def test_is_port_open_localhost_closed_port(mocker):
    mock_socket = mocker.MagicMock(spec=socket.socket)
    mock_socket.connect.side_effect = TimeoutError(
        "Connection failed"
    )  # Simulate connection failure by raising an exception
    mocker.patch("socket.socket", return_value=mock_socket)
    assert not is_port_open("127.0.0.1", 80)


def test_is_port_open_localhost_open_port(mocker):
    mock_socket = mocker.MagicMock(spec=socket.socket)
    mock_socket.connect.return_value = None  # Simulate successful connection
    mocker.patch("socket.socket", return_value=mock_socket)
    assert is_port_open("127.0.0.1", 20)


def test_is_port_open_invalid_ip():
    with pytest.raises(ValueError):
        is_port_open("invalid", 20)


def test_is_port_open_invalid_port_type():
    with pytest.raises(TypeError):
        is_port_open("127.0.0.1", "20")  # type: ignore


def test_is_port_open_port_not_in_range():
    with pytest.raises(ValueError):
        is_port_open("127.0.0.1", -1)
    with pytest.raises(ValueError):
        is_port_open("127.0.0.1", 100000)


def test_arp_scan(mocker):
    # Mock response packets
    mock_response = (
        [
            (mocker.MagicMock(), mocker.MagicMock(psrc="192.168.0.1")),
            (mocker.MagicMock(), mocker.MagicMock(psrc="192.168.0.2")),
        ],
        None,
    )

    # Set the return value of srp to the mocker response
    mocker.patch("port_scanner.networking.srp", return_value=mock_response)

    # Perform the ARP scan
    result = arp_scan("192.168.0.0/24")

    # Check if the function returns the expected list of IP addresses
    assert result == ["192.168.0.1", "192.168.0.2"]


def test_arp_scan_wrong_type():
    with pytest.raises(ValueError):
        arp_scan("invalid")


def test_tcp_syn_scan_open_port(mocker):
    # Mock a response with SYN-ACK flag set (indicating an open port)
    mock_response = mocker.MagicMock()
    mock_response.haslayer.return_value = True
    mock_response[TCP].flags = "SA"  # SYN-ACK flag

    # Set the return value of sr1 to the mocker response
    mocker.patch("port_scanner.networking.sr1", return_value=mock_response)

    # Perform the TCP SYN scan
    result = tcp_syn_scan("192.168.1.1", 80)

    # Check if the function returns True for an open port
    assert result


def test_tcp_syn_scan_closed_port(mocker):
    # Mock a response with RST flag set (indicating a closed port)
    mock_response = mocker.MagicMock()
    mock_response.haslayer.return_value = True
    mock_response[TCP].flags = "RA"  # RST flag

    # Set the return value of sr1 to the mocker response
    mocker.patch("port_scanner.networking.sr1", return_value=mock_response)

    # Perform the TCP SYN scan
    result = tcp_syn_scan("192.168.1.1", 80)

    # Check if the function returns False for a closed port
    assert not result


def test_tcp_syn_scan_filtered_port(mocker):
    # Mock a response with R flag set (indicating a filtered port)
    mock_response = mocker.MagicMock()
    mock_response.haslayer.return_value = True
    mock_response[TCP].flags = "R"  # Reset flag

    # Set the return value of sr1 to the mock response
    mocker.patch("port_scanner.networking.sr1", return_value=mock_response)

    # Perform the TCP SYN scan
    result = tcp_syn_scan("192.168.1.1", 80)

    # Check if the function returns False for a filtered port
    assert not result


def test_tcp_syn_scan_no_tcp(mocker):
    # Mock a response with R flag set (indicating a filtered port)
    mock_response = mocker.MagicMock()
    mock_response.haslayer.return_value = False

    # Set the return value of sr1 to the mock response
    mocker.patch("port_scanner.networking.sr1", return_value=mock_response)

    # Perform the TCP SYN scan
    result = tcp_syn_scan("192.168.1.1", 80)

    # Check if the function returns False for a filtered port
    assert not result


def test_tcp_syn_scan_other_status(mocker):
    # Mock a response with R flag set (indicating a filtered port)
    mock_response = mocker.MagicMock()
    mock_response.haslayer.return_value = True
    mock_response[TCP].flags = "X"

    # Set the return value of sr1 to the mock response
    mocker.patch("port_scanner.networking.sr1", return_value=mock_response)

    # Perform the TCP SYN scan
    result = tcp_syn_scan("192.168.1.1", 80)

    # Check if the function returns False for a filtered port
    assert not result


def test_tcp_syn_scan_no_response(mocker):
    # Set sr1 to return None (indicating no response)
    mocker.patch("port_scanner.networking.sr1", return_value=None)

    # Perform the TCP SYN scan
    result = tcp_syn_scan("192.168.1.1", 80)

    # Check if the function returns False for no response
    assert not result
