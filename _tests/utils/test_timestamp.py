from datetime import datetime, timezone
from utils.timestamp import (
    get_current_timestamp,
    format_timestamp,
    parse_timestamp,
    duration_timestamp,
)


def test_get_current_timestamp():
    """Test that get_current_timestamp returns a UTC datetime object."""
    ts = get_current_timestamp()
    assert isinstance(ts, datetime)
    assert ts.tzinfo == timezone.utc


def test_format_timestamp_with_timezone():
    """Test that format_timestamp returns correct ISO format for aware datetime."""
    dt = datetime(2025, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    formatted = format_timestamp(dt)
    assert formatted == "2025-04-14T12:00:00+00:00"


def test_format_timestamp_naive_datetime():
    """Test that format_timestamp converts naive datetime to UTC before formatting."""
    dt = datetime(2025, 4, 14, 12, 0, 0)  # naive
    formatted = format_timestamp(dt)
    assert formatted == "2025-04-14T12:00:00+00:00"


def test_parse_timestamp():
    """Test that parse_timestamp converts ISO string to aware datetime in UTC."""
    ts = "2025-04-14T12:00:00+00:00"
    dt = parse_timestamp(ts)
    assert dt == datetime(2025, 4, 14, 12, 0, 0, tzinfo=timezone.utc)


def test_duration_timestamp():
    """Test that duration_timestamp calculates seconds between two timestamps."""
    start = parse_timestamp("2025-04-14T12:00:00+00:00")
    end = parse_timestamp("2025-04-14T12:00:10+00:00")
    duration = duration_timestamp(start, end)
    assert duration == 10.0


def test_duration_timestamp_zero():
    """Test that duration is zero when start and end are the same."""
    ts = parse_timestamp("2025-04-14T12:00:00+00:00")
    assert duration_timestamp(ts, ts) == 0.0


def test_duration_timestamp_negative():
    """Test that duration can be negative if end is before start."""
    start = parse_timestamp("2025-04-14T12:00:10+00:00")
    end = parse_timestamp("2025-04-14T12:00:00+00:00")
    assert duration_timestamp(start, end) == -10.0
