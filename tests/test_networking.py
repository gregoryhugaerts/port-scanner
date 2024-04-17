import socket

import hypothesis.strategies as st
import pytest
from hypothesis import given
from port_scanner.networking import is_ip_address, is_port_open, ping


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
