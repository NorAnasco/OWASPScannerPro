import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanners.nmap_scanner import NmapScanner


def test_nmap_scan_does_not_hang_when_nmap_is_unavailable():
    scanner = NmapScanner('https://example.com')
    findings = scanner.run()
    assert isinstance(findings, list)
    assert findings  # fallback behavior should still return findings


def test_nmap_real_scan_uses_bounded_quick_options():
    scanner = NmapScanner('https://example.com')
    with patch('scanners.nmap_scanner.subprocess.run', return_value=SimpleNamespace(stdout='<nmaprun />', returncode=0)) as mock_run:
        findings = scanner._run_real()

    assert isinstance(findings, list)
    assert mock_run.called
    assert mock_run.call_args.kwargs['timeout'] <= 180
    command = mock_run.call_args.args[0]
    assert '-sV' in command
    assert '--host-timeout=120s' in command
    assert '--max-retries=1' in command
    assert '-p' in command
