import logging


FMT_GRAY = "\x1b[38;20m"
FMT_YELLOW = "\x1b[33;20m"
FMT_RED = "\x1b[31;20m"
FMT_BOLD_RED = "\x1b[31;1m"
FMT_RESET = "\x1b[0m"


class ColoredFormatter(logging.Formatter):
    def __init__(self, real_format):
        self.real_format = real_format

        self.format_map = {
            logging.DEBUG: FMT_GRAY + real_format + FMT_RESET,
            logging.INFO: FMT_GRAY + real_format + FMT_RESET,
            logging.WARNING: FMT_YELLOW + real_format + FMT_RESET,
            logging.ERROR: FMT_RED + real_format + FMT_RESET,
            logging.CRITICAL: FMT_BOLD_RED + real_format + FMT_RESET
        }

    def format(self, record):
        log_fmt = self.format_map.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def get_logger(name=None):
    logger = logging.getLogger(name)
    if not logger.hasHandlers():
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(ColoredFormatter("%(asctime)s [%(levelname)s] <%(filename)s:%(lineno)d> %(message)s"))
        logger.addHandler(console_handler)
        logger.setLevel(logging.INFO)
    return logger
