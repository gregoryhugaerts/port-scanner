import ipaddress
import sys
from typing import Annotated

import typer
from rich.console import Console
from rich.live import Live
from rich.table import Table

from port_scanner.decorators import rate_limit
from port_scanner.logger import get_logger
from port_scanner.networking import is_ip_address, is_port_open, ping, tcp_syn_scan

LOGGER = get_logger("port-scan.log")

app = typer.Typer(no_args_is_help=True)

console = Console()


def _typer_check_host(host: str) -> str:
    """Wrap `is_ip_address` for typer.

    Args:
    ----
        host (str): the host string to check

    Raises:
    ------
        typer.BadParameter: raised if host is not an ip address
    """
    if not is_ip_address(host):
        msg = "Host needs to be an ip address"
        raise typer.BadParameter(msg)
    else:
        return host


def _typer_check_range(ip_range: str):
    """Check if `ip_range` is a valid ipv4network for typer

    Args:
        ip_range (str): the range to check

    Raises:
        typer.BadParameter: raised if `ip_range` is not a network
    """
    try:
        ipaddress.IPv4Network(ip_range)
        return ip_range
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        msg = "Host needs to be a valid ip range (ip/mask)"
        raise typer.BadParameter(msg) from None


@app.command()
def scan_arp(ip_range: Annotated[str, typer.Option(callback=_typer_check_range, prompt=True)]):
    """perform an arp scan of the ip-range."""
    from port_scanner import networking

    devices = networking.arp_scan(ip_range)
    table = Table()
    table.add_column("device ip address")
    for device in devices:
        table.add_row(device)
    console.print(table)


@app.command()
def port_scan(
    host: Annotated[str, typer.Option(callback=_typer_check_host, prompt=True)],
    start_port: Annotated[int, typer.Option(prompt=True)],
    end_port: Annotated[int, typer.Option(prompt=True)],
    wait_between_ports: Annotated[float, typer.Option()] = 0,
    use_tcp_syn: bool = False,  # noqa: FBT001, FBT002
    skip_ping: bool = False,  # noqa: FBT002, FBT001
) -> None:
    """Scan host's ports from start-port to end-port"""
    if not skip_ping:
        if ping(host):
            console.print(f"{host} seems to be up")
            LOGGER.info(f"{host} seems to be up")
        else:
            console.print(f"{host} could not be pinged")
            LOGGER.error(f"{host} could not be pinged")
            sys.exit(1)

    if use_tcp_syn:
        scan = tcp_syn_scan
    else:
        scan = is_port_open
    if wait_between_ports:
        scan = rate_limit(wait_between_ports)(scan)
    table = Table()
    table.add_column("Port")
    table.add_column("Status")
    with Live(table, refresh_per_second=4):
        ports = range(max(1, start_port), min(65535, end_port + 1))
        for port in ports:
            response = scan(host, port)
            if response:
                LOGGER.info(f"port {port} on {host} is open")
                table.add_row(f"{port}", "[green]open[/]")
            else:
                LOGGER.info(f"port {port} on {host} is closed")
                table.add_row(f"{port}", "[red]closed[/]")


@app.command()
def tui():
    from port_scanner.tui.tui import TUI

    TUI().run()
