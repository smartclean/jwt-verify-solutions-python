import logging


def _get_std_log_level_from_input(log_level_input: str) -> int:

    input_all_caps = log_level_input.upper()

    log_level_by_input = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR
    }

    if input_all_caps in log_level_by_input:
        return log_level_by_input[input_all_caps]

    return logging.CRITICAL


def get_logger_for_module(module_name: str, log_level_input: str):

    _std_log_level = _get_std_log_level_from_input(log_level_input)

    module_logger = logging.getLogger(module_name)

    if module_logger.hasHandlers():
        module_logger.setLevel(_std_log_level)
        return module_logger

    logging.basicConfig(level=_std_log_level)

    module_logger = logging.getLogger(module_name)

    return module_logger
