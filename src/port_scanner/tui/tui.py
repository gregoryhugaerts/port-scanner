import typing
from dataclasses import dataclass
from operator import attrgetter

from textual.app import App, ComposeResult
from textual.message import Message
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Input, Label, ListItem, ListView, Static

from port_scanner.networking import MAX_PORT, MIN_PORT, is_port_open


@dataclass
class _Port:
    port: int
    status: str = "Pending"

    def __post_init__(self):
        if self.port < MIN_PORT or self.port > MAX_PORT:
            msg = f"Ports should be between {MIN_PORT} and {MAX_PORT}"
            raise ValueError(msg)

    def __hash__(self) -> int:
        return self.port.__hash__()


@dataclass
class _Target:
    ip: str
    ports: set[_Port]

    def __hash__(self) -> int:
        return self.ip.__hash__()


# targets = [_Target("127.0.0.1", {_Port(10), _Port(20)}), _Target("10.10.10.10", {_Port(10), _Port(30)})]
targets = []


class Sidebar(Static):
    class Highlighted(Message):
        """Color selected message."""

        def __init__(self, index: int) -> None:
            self.index = index
            super().__init__()

    def _make_target_items(self, targets: list[_Target]) -> list[ListItem]:
        return [ListItem(Label(target.ip)) for target in targets]

    def compose(self) -> ComposeResult:
        target_items = self._make_target_items(targets)
        yield ListView(*target_items)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        index = event.list_view.index
        if index is not None:
            self.post_message(self.Highlighted(index))


class TargetModal(ModalScreen):
    def compose(self):
        yield Static("Please enter an ip address to scan")
        yield Input(placeholder="ip address")

    def on_input_submitted(self, event: Input.Submitted):
        self.dismiss(event.value)


class PortModal(ModalScreen):
    def compose(self):
        yield Static("Please enter an port range to add to the scan")
        yield Input(placeholder="start-end")

    def on_input_submitted(self, event: Input.Submitted):
        self.dismiss(event.value)


class TUI(App):
    CSS_PATH = "tui.tcss"

    BINDINGS: typing.ClassVar = [
        ("a", "add_target()", "Add _Target"),
        ("d", "remove_target", "Remove Target"),
        ("p", "add_ports", "Add Ports"),
        ("q", "quit", "Quit"),
    ]

    current_target = reactive[_Target | None](None)

    def action_add_target(self):
        def add_target(target_ip: str):
            targets.append(_Target(target_ip, set()))
            self.refresh(recompose=True)

        self.push_screen(TargetModal(), add_target)

    def action_remove_target(self):
        index = targets.index(self.current_target)
        targets.remove(self.current_target)
        self.current_target = targets[min(index, len(targets))]
        self._update_table()
        self.refresh(recompose=True)

    def action_add_ports(self):
        def add_port(port_range: str):
            if self.current_target is None:
                return
            if "-" in port_range:
                (start_port, end_port) = port_range.split("-")
                for port in range(int(start_port), int(end_port) + 1):
                    self.current_target.ports.add(_Port(port))
            else:
                self.current_target.ports.add(_Port(int(port_range)))
            self._scan_ports()

        if self.current_target is None:
            return
        self.push_screen(PortModal(), add_port)

    def compose(self) -> ComposeResult:
        yield Sidebar()
        yield DataTable()
        yield Header()
        yield Footer()

    def _update_table(self):
        table = self.query_one(DataTable)
        table.clear(True)
        table.add_column("Port")
        table.add_column("Status")
        if self.current_target is None:
            return
        ports = sorted(self.current_target.ports, key=attrgetter("port"))
        for port in ports:
            table.add_row(port.port, port.status)
        table.refresh()

    def watch_current_target(self, old: _Target, new: _Target) -> None:  # noqa: ARG002
        if self.current_target is None:
            return
        self._scan_ports()

    def _scan_ports(self):
        self._update_table()
        if self.current_target is None:
            return
        for port in self.current_target.ports:
            if port.status == "Pending":
                status = is_port_open(self.current_target.ip, port.port)
                port.status = "[green]Open[/]" if status else "[red]Closed[/]"
                self._update_table()

    def on_sidebar_highlighted(self, event: Sidebar.Highlighted) -> None:
        index = event.index
        self.current_target = targets[index]


if __name__ == "__main__":
    app = TUI()
    app.run()
