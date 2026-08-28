import platform

from scanner.windows_scanner import WindowsScanner


class ScannerManager:

    def __init__(self):

        operating_system = platform.system()

        if operating_system == "Windows":

            self.scanner = WindowsScanner()

        else:

            raise RuntimeError(
                f"Operating system '{operating_system}' "
                "is not supported yet."
            )

    def scan(self) -> str:

        return self.scanner.scan()

    def get_interfaces(self) -> str:

        return self.scanner.get_interfaces()