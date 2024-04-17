import sys
from typing import Annotated

import typer

from port_scanner.logger import get_logger
from port_scanner.networking import is_ip_address, is_port_open, ping

LOGGER = get_logger("port-scan.log")


def _typer_check_host(host: str) -> str:
    """Wrap `is_ip_address` for typer.

    Args:
    ----
        host (str): the host string to check

    Raises:
    ------
        typer.BadParameter: raised if host is not an ip address

    Returns:
    -------
        str: the host string if it is an ip address

    """
    if not is_ip_address(host):
        msg = "Host needs to be an ip address"
        raise typer.BadParameter(msg)
    else:
        return host


def main(
    host: Annotated[str, typer.Option(callback=_typer_check_host, prompt=True)],
    start_port: Annotated[int, typer.Option(prompt=True)],
    end_port: Annotated[int, typer.Option(prompt=True)],
) -> None:
    if ping(host):
        LOGGER.info(f"{host} seems to be up")
    else:
        LOGGER.error(f"{host} could not be pinged")
        sys.exit()
    ports = range(max(1, start_port), min(65535, end_port + 1))
    for port in ports:
        if is_port_open(host, port):
            LOGGER.info(f"port {port} on {host} is open")
        else:
            LOGGER.info(f"port {port} on {host} is closed")


if __name__ == "__main__":
    typer.run(main)
