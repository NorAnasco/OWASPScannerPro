import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanners.nikto_scanner import NiktoScanner


def test_nikto_uses_wsl_fallback_when_nikto_is_not_on_windows_path():
    scanner = NiktoScanner('https://example.com')
    with patch('scanners.nikto_scanner.shutil.which', side_effect=lambda name: 'wsl.exe' if name == 'wsl.exe' else None):
        command = scanner._resolve_nikto_command()

    assert command is not None
    assert command[:2] == ['wsl.exe', 'bash']
