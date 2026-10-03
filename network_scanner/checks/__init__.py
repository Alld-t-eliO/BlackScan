from network_scanner.checks.builtin import BUILTIN_CHECKS


def load_checks():
    return [check_class() for check_class in BUILTIN_CHECKS]
