# Standard library
from datetime import datetime, timezone


def get_current_timestamp() -> datetime:
    """Get the current UTC timestamp as a timezone-aware datetime object.

    Returns:
        datetime: Current UTC time with timezone information.

    Notes:
        Suitable for inserting directly into SQL `timestamp with time zone` columns.
    """
    return datetime.now(timezone.utc)


def format_timestamp(dt: datetime, tz: timezone = timezone.utc) -> str:
    """Format a datetime object as an ISO 8601 string.

    If the datetime is naive (no timezone), the specified timezone will be applied.

    Args:
        dt (datetime): Datetime object to format.
        tz (timezone, optional): Timezone to apply if `dt` is naive. Defaults to UTC.

    Returns:
        str: ISO 8601 formatted datetime string.
             Example: '2025-04-15T14:32:19.123456+00:00'
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    return dt.isoformat()


def parse_timestamp(timestamp_str: str) -> datetime:
    """Parse an ISO 8601 formatted timestamp string into a datetime object.

    Args:
        timestamp_str (str): ISO 8601 formatted timestamp.

    Returns:
        datetime: Parsed datetime object.

    Raises:
        ValueError: If the input string is not properly formatted.
    """
    return datetime.fromisoformat(timestamp_str)


def duration_timestamp(start_ts: datetime, end_ts: datetime) -> float:
    """Calculate the duration in seconds between two datetime timestamps.

    Args:
        start_ts (datetime): Start time.
        end_ts (datetime): End time.

    Returns:
        float: Duration in seconds.
    """
    return (end_ts - start_ts).total_seconds()