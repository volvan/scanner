from unittest.mock import patch
import pytest
from utils.ports_handler import read_ports_file


@pytest.fixture
def ports_file(tmp_path):
    """Create a ports.txt file with comma-separated values for testing."""
    file_path = tmp_path / "ports.txt"
    content = "80,443,8080\n22,53\n"
    file_path.write_text(content)
    return file_path.name, tmp_path


@pytest.fixture
def port_range_file(tmp_path):
    """Create a ports.txt file with a port range in the first line."""
    file_path = tmp_path / "ports.txt"
    content = "1000-1002\n22,53\n"
    file_path.write_text(content)
    return file_path.name, tmp_path


@pytest.fixture
def bad_ports_file(tmp_path):
    """Create a ports.txt file with invalid lines."""
    file_path = tmp_path / "ports.txt"
    content = "bad-input\nanother-bad-line\n"
    file_path.write_text(content)
    return file_path.name, tmp_path


def test_read_ports_comma_list(monkeypatch, ports_file):
    """Test that read_ports_file parses comma-separated ports correctly."""
    filename, tmp_path = ports_file
    monkeypatch.setattr("utils.ports_handler.TARGETS_FILE_PATH", str(tmp_path))
    ports, custom = read_ports_file(filename)
    assert ports == [80, 443, 8080]
    assert custom == [22, 53]


def test_read_ports_range(monkeypatch, port_range_file):
    """Test that read_ports_file parses a port range into a list."""
    filename, tmp_path = port_range_file
    monkeypatch.setattr("utils.ports_handler.TARGETS_FILE_PATH", str(tmp_path))
    ports, custom = read_ports_file(filename)
    assert ports == [1000, 1001, 1002]
    assert custom == [22, 53]


def test_read_ports_missing_lines(tmp_path, monkeypatch):
    """Test read_ports_file returns None when the second line is missing."""
    file_path = tmp_path / "ports.txt"
    file_path.write_text("80,443\n")  # Only one line
    monkeypatch.setattr("utils.ports_handler.TARGETS_FILE_PATH", str(tmp_path))
    ports, custom = read_ports_file(file_path.name)
    assert ports is None
    assert custom is None


def test_read_ports_invalid(monkeypatch, bad_ports_file):
    """Test read_ports_file returns empty lists when all lines are invalid."""
    filename, tmp_path = bad_ports_file
    monkeypatch.setattr("utils.ports_handler.TARGETS_FILE_PATH", str(tmp_path))
    ports, custom = read_ports_file(filename)
    assert ports == []
    assert custom == []


def test_read_ports_file_not_found(monkeypatch):
    """Test read_ports_file returns None if file does not exist."""
    monkeypatch.setattr("config.scan_config.TARGETS_FILE_PATH", "/nonexistent")
    ports, custom = read_ports_file("fake.txt")
    assert ports is None
    assert custom is None


@patch("utils.ports_handler.logger")
def test_force_ports_list_exception_only(mock_logger, tmp_path, monkeypatch):
    """Ensure error in ports list (comma-separated) triggers specific exception block (lines 44-45)."""
    file_path = tmp_path / "ports.txt"
    file_path.write_text("443,invalid,8080\n22,53\n")

    monkeypatch.setattr("utils.ports_handler.TARGETS_FILE_PATH", str(tmp_path))
    ports, custom = read_ports_file(file_path.name)

    # Confirm the parsing failed on first line, second is okay
    assert ports == []
    assert custom == [22, 53]

    # Assert logger.error was called with expected substring
    assert any("Error parsing ports list" in call.args[0] for call in mock_logger.error.call_args_list)
