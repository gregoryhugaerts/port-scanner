import ipaddress
import platform
import re
import socket
import subprocess

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


def arp_scan(ip_range: str):
    devices = []
    for ip in ipaddress.IPv4Network(ip_range):
        try:
            output = subprocess.check_output(["arp", "-a", str(ip)])  # noqa: S607, S603
            output = output.decode("utf-8")
            lines = output.split("\n")
            for line in lines:
                match = re.match(r"^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9a-fA-F:]+)", line)
                if match:
                    ip_address = match.group(1)
                    devices.append(ip_address)
        except subprocess.CalledProcessError:
            pass

    return devices
