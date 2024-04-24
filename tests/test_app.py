import pytest
import typer
from port_scanner.app import _typer_check_host, _typer_check_range, app
from typer.testing import CliRunner

runner = CliRunner()

_LOCALHOST = "127.0.0.1"


def test_app_portscan_localhost_with_open_port(mocker):
    mocker.patch("port_scanner.app.is_port_open", return_value=True)
    mocker.patch("port_scanner.app.ping", return_value=True)

    result = runner.invoke(app, ["port-scan", "--host", f"{_LOCALHOST}", "--start-port", "20", "--end-port", "20"])
    assert result.exit_code == 0
    assert "20" in result.stdout
    assert "open" in result.stdout
    assert "closed" not in result.stdout


def test_app_portscan_localhost_with_closed_port(mocker):
    mocker.patch("port_scanner.app.is_port_open", return_value=False)
    mocker.patch("port_scanner.app.ping", return_value=True)

    result = runner.invoke(app, ["port-scan", "--host", f"{_LOCALHOST}", "--start-port", "20", "--end-port", "20"])
    assert result.exit_code == 0
    assert "20" in result.stdout
    assert "closed" in result.stdout
    assert "open" not in result.stdout


def test_app_portscan_localhost_with_multiple_port(mocker):
    mocker.patch("port_scanner.app.is_port_open", return_value=False)
    mocker.patch("port_scanner.app.ping", return_value=True)

    result = runner.invoke(app, ["port-scan", "--host", f"{_LOCALHOST}", "--start-port", "20", "--end-port", "21"])
    assert result.exit_code == 0
    assert "20" in result.stdout
    assert "21" in result.stdout


def test_app_portscan_ping_failure(mocker):
    mocker.patch("port_scanner.app.ping", return_value=False)

    result = runner.invoke(app, ["port-scan", "--host", f"{_LOCALHOST}", "--start-port", "20", "--end-port", "20"])
    assert result.exit_code == 1


def test_app_tcp_syn_scan(mocker):
    mocker.patch("port_scanner.app.tcp_syn_scan", return_value=False)
    result = runner.invoke(
        app,
        [
            "port-scan",
            "--host",
            f"{_LOCALHOST}",
            "--start-port",
            "20",
            "--end-port",
            "20",
            "--use-tcp-syn",
            "--skip-ping",
        ],
    )
    assert result.exit_code == 0


def test_app_tcp_syn_scan_timeout(mocker):
    mocker.patch("port_scanner.app.tcp_syn_scan", return_value=False)
    result = runner.invoke(
        app,
        [
            "port-scan",
            "--host",
            f"{_LOCALHOST}",
            "--start-port",
            "20",
            "--end-port",
            "21",
            "--use-tcp-syn",
            "--skip-ping",
            "--wait-between-ports",
            "2",
        ],
    )
    assert result.stdout


def test_app_arp_scan(mocker):
    mocker.patch("port_scanner.networking.arp_scan", return_value=["10.10.10.10", "10.1.1.1"])
    result = runner.invoke(app, ["scan-arp", "--ip-range", "10.10.10.0/24"])
    assert result.exit_code == 0


def test_typer_check_host():
    with pytest.raises(typer.BadParameter):
        _typer_check_host("invalid")


def test_typer_check_range():
    with pytest.raises(typer.BadParameter):
        _typer_check_range("invalid")
