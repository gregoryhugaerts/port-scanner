import ipaddress
import platform
import re
import socket
import subprocess

from scapy.all import ARP, ICMP, IP, TCP, Ether, sr1, srp  # type: ignore

from port_scanner.decorators import rate_limit

# regex that matches ipv4 addresses
IPV4_ADDRESS_PATTERN = re.compile(
    r""" # first octet
                     (25[0-5] # 250-255
                     |2[0-4][0-9] # 200-249
                     |[01]?[0-9][0-9]?) # 0-199
                     # other 3 octets
                     (\. # literal point
                     (25[0-5] # 250-255
                     |2[0-4][0-9] # 200-249
                     |[01]?[0-9][0-9]?)){3} # 0-199

""",
    re.VERBOSE,
)

MIN_PORT = 1  # lowest port that can be used
MAX_PORT = 65535  # highers port that can be used


def is_ip_address(address: str) -> bool:
    """Check whether `address` represents an ipv4 address.

    Args:
    ----
        address (str): _the ip_address to check

    Returns:
    -------
        bool: True if is an ipv4 address, False otherwise

    """
    if not isinstance(address, str):
        return False
    return re.match(IPV4_ADDRESS_PATTERN, address) is not None


def ping(host: str) -> bool:
    """Pings a `host`.
    Args:
    ----
        host (str): ip address of the host
    Raises:
    ------
        TypeError: raised when host isn't an ip address
    Returns:
    -------
        bool: whether ping was successful
    """
    if not is_ip_address(host):
        msg = "Host needs to be an ip address"
        raise ValueError(msg)
    # Option for the number of packets
    param = "-n" if platform.system().lower() == "windows" else "-c"

    # Building the command. Ex: "ping -c 1 google.com"
    command = ["ping", param, "1", host]

    return subprocess.call(command, stdout=subprocess.DEVNULL) == 0  # noqa: S603


def __ping(host: str) -> bool:
    """Do not use, it's flaky"""
    if not is_ip_address(host):
        msg = "Host needs to be an ip address"
        raise ValueError(msg)
    # Craft an ICMP Echo Request packet (ping packet)
    icmp_packet = IP(dst=host) / ICMP(type=8)

    # Send the packet and receive a response
    response = sr1(icmp_packet, timeout=3, verbose=False)

    if response is not None:
        # Analyze the response
        if response.haslayer(ICMP):
            if response[ICMP].type == 0:  # ICMP Echo Reply
                return True
            elif response[ICMP].type == 3:  # ICMP Destination Unreachable  # noqa: PLR2004
                return False
    return False


@rate_limit(1)
def is_port_open(host: str, port: int) -> bool:
    """Determine whether `host` has the `port` open.

    Args:
    ----
        host (str): the ip address of the host to scan
        port (int): the port to scan

    Returns:
    -------
        bool: whether the port is open

    """
    if not is_ip_address(host):
        msg = "host needs to be a valid ipv4 ip address"
        raise ValueError(msg)
    if not isinstance(port, int):
        msg = "port needs to be an integer"
        raise TypeError(msg)
    if port < MIN_PORT or port > MAX_PORT:
        msg = "port needs to be in between 1 and 65535"
        raise ValueError(msg)
    # creates a new socket
    s = socket.socket()
    try:
        s.settimeout(1)
        # tries to connect to host using that port
        s.connect((host, port))
    except TimeoutError:
        # cannot connect, port is closed
        # return false
        return False
    else:
        # the connection was established, port is open!
        return True


def arp_scan(ip_network: str) -> list[str]:
    """Perform an arp scan on `ip_network`

    Args:
        ip_network (str): valid ip network for `ip_address.ip_network`

    Raises:
        ValueError: if the string passed isn't either a v4 or a v6
      address

    Returns:
        list[str]: List of ip addresses on the network
    """
    try:
        ipaddress.ip_network(ip_network)
    except ValueError:
        msg = "Not a valid ip network"
        raise ValueError(msg) from None
    arp_request = ARP(pdst=ip_network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = ether / arp_request
    answered_list, _ = srp(arp_broadcast, timeout=1, verbose=False)

    devices = []
    for _, received in answered_list:
        devices.append(received.psrc)

    return devices


@rate_limit(1)
def tcp_syn_scan(target_ip: str, target_port: int) -> bool:
    # Craft a TCP SYN packet
    syn_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")

    # Send the packet and receive a response
    response = sr1(syn_packet, timeout=2, verbose=False)

    if response is not None:
        # Analyze the response
        if response.haslayer(TCP):
            if response[TCP].flags == "SA":
                return True
            elif response[TCP].flags == "RA":
                return False
            elif response[TCP].flags == "R":
                return False
    return False
