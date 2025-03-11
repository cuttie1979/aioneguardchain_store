#########################################
# Author: Laszlo Popovics               #
# Version: 1.0                          #
# Program: AIOneGuard - Logger v2 Class #
#########################################

# Import the required libraries
from inspect import stack
from os import getcwd
from aioneguard.utils import logger
from os import getenv

# Initialize the logger class
_logger = logger.Logger.get_instance()
_root = getcwd()


def log_info(log_msg: str):
    _logger.info(f"[{stack()[1].filename.replace(_root, '')[1:-3]}] - {log_msg}")


def log_error(log_msg: str):

    _logger.error(f"[{stack()[1].filename.replace(_root, '')[1:-3]}] - {log_msg}")


def log_warning(log_msg: str):
    _logger.warning(f"[{stack()[1].filename.replace(_root, '')[1:-3]}] - {log_msg}")


def log_debug(log_msg: str):
    if getenv("DEBUG"):
        _logger.debug(f"[{stack()[1].filename.replace(_root, '')[1:-3]}] - {log_msg}")
