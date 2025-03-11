#   AIOneGuard - Logger v2 Class
from dataclasses import dataclass
from datetime import datetime
from os import getcwd, getenv
from pytz import timezone


@dataclass(frozen=True)
class Severity:
    INFO = "info"
    ERROR = "error"
    WARNING = "warning"
    DEBUG = "debug"


class Logger:
    def __init__(self):
        self.tz = timezone('Europe/Madrid')
        self._get_debug = bool(getenv("DEBUG"))

    @staticmethod
    def get_instance():
        if not hasattr(Logger, '_instance'):
            Logger._instance = Logger()
        return Logger._instance

    def get_ts(self):
        return datetime.now(self.tz).strftime("%Y.%m.%d %H:%M:%S.%f")[:-3]

    def log(self, message, severity):
        print(f"{self.get_ts()} [{severity.upper()}] - {message}")

    def info(self, message):
        self.log(message, Severity.INFO)

    def error(self, message):
        self.log(message, Severity.ERROR)

    def warning(self, message):
        self.log(message, Severity.WARNING)

    def debug(self, message):
        if self._get_debug:
            self.log(message, Severity.DEBUG)


logger = Logger.get_instance()
root = getcwd()


def _format_msg(log_msg):
    caller = __import__('inspect').stack()[2].filename.replace(root, '')[1:-3]
    return f"[{caller}] - {log_msg}"


def log_info(log_msg): logger.info(_format_msg(log_msg))
def log_error(log_msg): logger.error(_format_msg(log_msg))
def log_warning(log_msg): logger.warning(_format_msg(log_msg))
def log_debug(log_msg): logger.debug(_format_msg(log_msg))
