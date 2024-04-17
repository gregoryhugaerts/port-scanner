"""functions related to logging."""

import logging

from rich.logging import RichHandler


def get_logger(filename: str) -> logging.Logger:
    """Get the program logger.

    Args:
    ----
        filename (str): The file to log to

    Returns:
    -------
        logging.Logger: a logger instance

    """
    logger = logging.getLogger(__name__)

    # the handler determines where the logs go: stdout/file
    shell_handler = RichHandler()
    file_handler = logging.FileHandler(filename)

    logger.setLevel(logging.DEBUG)
    shell_handler.setLevel(logging.DEBUG)
    file_handler.setLevel(logging.DEBUG)

    # the formatter determines what our logs will look like
    fmt_shell = "%(message)s"
    fmt_file = "%(levelname)s %(asctime)s [%(filename)s:%(funcName)s:%(lineno)d] %(message)s"

    shell_formatter = logging.Formatter(fmt_shell)
    file_formatter = logging.Formatter(fmt_file)

    # here we hook everything together
    shell_handler.setFormatter(shell_formatter)
    file_handler.setFormatter(file_formatter)

    logger.addHandler(shell_handler)
    logger.addHandler(file_handler)
    return logger
