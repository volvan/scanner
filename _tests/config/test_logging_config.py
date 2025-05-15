import logging
import sys
from unittest.mock import patch, MagicMock

from config import logging_config


def test_log_exception_keyboard_interrupt(monkeypatch):
    """Ensure KeyboardInterrupt is passed to default excepthook without logging."""
    mock_hook = MagicMock()
    monkeypatch.setattr(sys, "__excepthook__", mock_hook)

    exc = KeyboardInterrupt("Ctrl+C")
    logging_config.log_exception(KeyboardInterrupt, exc, None)

    mock_hook.assert_called_once_with(KeyboardInterrupt, exc, None)


def test_log_exception_generic(monkeypatch, caplog):
    """Ensure non-KeyboardInterrupt exceptions are logged."""
    caplog.set_level(logging.ERROR)
    dummy_exc = ValueError("Test Error")

    logging_config.log_exception(ValueError, dummy_exc, None)

    assert any("Unhandled Exception" in message for message in caplog.messages)


@patch("config.logging_config.logger")
def test_log_exception_generic_logs_error(mock_logger):
    """
    Test that non-KeyboardInterrupt exceptions are logged correctly.

    This verifies that the `log_exception` function logs an error message
    with the correct format and exception info when a generic exception
    (e.g., ValueError) is passed.
    """
    exc = ValueError("Test Error")
    logging_config.log_exception(ValueError, exc, None)

    mock_logger.error.assert_called_once()
    args, kwargs = mock_logger.error.call_args
    assert "Unhandled Exception" in args[0]
    assert kwargs["exc_info"] == (ValueError, exc, None)
