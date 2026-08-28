import subprocess


class WindowsScanner:

    def get_interfaces(self) -> str:
        """
        Returns information about wireless interfaces.
        """

        command = [
            "netsh",
            "wlan",
            "show",
            "interfaces"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        if result.returncode != 0:
            raise RuntimeError(
                "Unable to access wireless interfaces."
            )

        return result.stdout

    def scan(self) -> str:
        """
        Scans nearby Wi-Fi networks using Windows netsh.
        """

        command = [
            "netsh",
            "wlan",
            "show",
            "networks",
            "mode=bssid"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        if result.returncode != 0:
            raise RuntimeError(
                "Wi-Fi scan failed."
            )

        return result.stdout