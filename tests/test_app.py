import pytest
import typer
from port_scanner.app import _typer_check_host, app
from typer.testing import CliRunner

runner = CliRunner()

_LOCALHOST = "127.0.0.1"


def test_app_localhost_with_open_port(mocker):
    mocker.patch("port_scanner.app.is_port_open", return_value=True)

    result = runner.invoke(app, ["--host", f"{_LOCALHOST}", "--start-port", "20", "--end-port", "20"])
    assert result.exit_code == 0
    assert f"{_LOCALHOST} seems to be up" in result.stdout
    assert f"port 20 on {_LOCALHOST} is open" in result.stdout


def test_app_localhost_with_closed_port(mocker):
    mocker.patch("port_scanner.app.is_port_open", return_value=False)

    result = runner.invoke(app, ["--host", f"{_LOCALHOST}", "--start-port", "20", "--end-port", "20"])
    assert result.exit_code == 0
    assert f"{_LOCALHOST} seems to be up" in result.stdout
    assert f"port 20 on {_LOCALHOST} is closed" in result.stdout


def test_app_localhost_with_multiple_port(mocker):
    mocker.patch("port_scanner.app.is_port_open", return_value=False)

    result = runner.invoke(app, ["--host", f"{_LOCALHOST}", "--start-port", "20", "--end-port", "21"])
    assert result.exit_code == 0
    assert f"{_LOCALHOST} seems to be up" in result.stdout
    assert f"port 20 on {_LOCALHOST} is closed" in result.stdout
    assert f"port 21 on {_LOCALHOST} is closed" in result.stdout


def test_app_ping_failure(mocker):
    mocker.patch("port_scanner.app.ping", return_value=False)

    result = runner.invoke(app, ["--host", f"{_LOCALHOST}", "--start-port", "20", "--end-port", "20"])
    assert result.exit_code == 1
    assert f"{_LOCALHOST} could not be pinged" in result.stdout


def test_typer_check_host():
    with pytest.raises(typer.BadParameter):
        _typer_check_host("invalid")
