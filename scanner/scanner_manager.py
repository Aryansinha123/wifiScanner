import platform
from typing import Dict, Any
from scanner.windows_scanner import WindowsScanner


class ScannerManager:
    """
    Interface manager for OS-specific Wi-Fi scanners.
    Phase 1.5 supports Windows.
    """

    def __init__(self):
        operating_system = platform.system()

        if operating_system == "Windows":
            self.scanner = WindowsScanner()
        else:
            raise RuntimeError(
                f"Operating system '{operating_system}' is not supported yet."
            )

    def scan(self) -> str:
        """
        Triggers network scan using the OS scanner.
        """
        return self.scanner.scan()

    def get_interfaces(self) -> str:
        """
        Queries wireless interface status raw text.
        """
        return self.scanner.get_interfaces()

    def get_interface_info(self) -> Dict[str, Any]:
        """
        Queries parsed wireless interface status information.
        """
        return self.scanner.get_interface_info()