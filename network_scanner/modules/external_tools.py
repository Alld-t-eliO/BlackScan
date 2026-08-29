import shutil
import subprocess

SUPPORTED_TOOLS = ('nmap', 'nuclei', 'httpx', 'subfinder', 'dnsx')


def detect_external_tools():
    tools = {}
    for name in SUPPORTED_TOOLS:
        path = shutil.which(name)
        tools[name] = {
            'available': bool(path),
            'path': path or '',
            'version': get_tool_version(name) if path else '',
        }
    return tools


def get_tool_version(name):
    version_args = {
        'nmap': ['nmap', '--version'],
        'nuclei': ['nuclei', '-version'],
        'httpx': ['httpx', '-version'],
        'subfinder': ['subfinder', '-version'],
        'dnsx': ['dnsx', '-version'],
    }
    try:
        result = subprocess.run(
            version_args[name],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, KeyError):
        return ''

    output = (result.stdout or result.stderr).strip().splitlines()
    for line in output:
        clean = line.strip()
        if clean and any(char.isdigit() for char in clean):
            return clean[:160]
    return output[0][:160] if output else ''
