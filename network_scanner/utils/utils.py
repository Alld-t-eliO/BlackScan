#!/usr/bin/env python3


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

def colorize(text, color=Colors.WHITE):
    return f"{color}{text}{Colors.RESET}"

def print_success(text):
    print(f"{Colors.GREEN}[+] {text}{Colors.RESET}")

def print_error(text):
    print(f"{Colors.RED}[!] {text}{Colors.RESET}")

def print_info(text):
    print(f"{Colors.BLUE}[*] {text}{Colors.RESET}")

def print_warning(text):
    print(f"{Colors.YELLOW}[!] {text}{Colors.RESET}")

def print_vuln(text):
    print(f"{Colors.RED}[!] VULNERABILITY: {text}{Colors.RESET}")