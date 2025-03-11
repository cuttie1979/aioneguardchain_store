#########################################
# Author: Laszlo Popovics               #
# Version: 1.0                          #
# Program: AIOneGuard - Logger Class    #
#########################################

# Import the required libraries
from datetime import datetime
from pytz import timezone
import os
import dataclasses


@dataclasses.dataclass(frozen=True)
class Severity:
    INFO: str = "info"
    ERROR: str = "error"
    WARNING: str = "warning"
    DEBUG: str = "debug"


class Logger:

    _instance = None
    _debug_env = os.getenv("DEBUG")
    _debug = False
    if _debug_env:
        if int(_debug_env) == 1:
            _debug = True

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            cls.tz = timezone('Europe/Madrid')
            return cls._instance
        else:
            return cls._instance

    def get_ts(self) -> str:
        return datetime.now(self.tz).strftime("%Y.%m.%d %H:%M:%S.%f")[:-3]

    def get_log_message(self, message: str, severity: str) -> str:
        return f"{self.get_ts()} [{severity.upper()}] - {message}"

    def log_screen(self, message: str, severity: str):
        print(self.get_log_message(message=message, severity=severity))

    def info(self, message: str):
        self.log_screen(message, Severity.INFO)

    def error(self, message: str):
        self.log_screen(message, Severity.ERROR)

    def warning(self, message: str):
        self.log_screen(message, Severity.WARNING)

    def debug(self, message: str):
        if self._debug:
            self.log_screen(message, Severity.DEBUG)
