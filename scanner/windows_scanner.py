import logging
import subprocess

logger = logging.getLogger(__name__)


class WindowsScanner:
    """
    Handles passive Wi-Fi discovery on Windows using netsh CLI commands.
    """

    def get_interfaces(self) -> str:
        """
        Executes 'netsh wlan show interfaces' and returns raw text output.
        """
        command = ["netsh", "wlan", "show", "interfaces"]
        logger.debug("Executing command: %s", " ".join(command))

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                check=False
            )
        except Exception as err:
            logger.error("Failed to execute netsh show interfaces: %s", err)
            raise RuntimeError(f"Unable to access wireless interfaces: {err}") from err

        if result.returncode != 0:
            stderr_msg = result.stderr.strip() if result.stderr else "Unknown error"
            logger.error("netsh show interfaces failed with code %d: %s", result.returncode, stderr_msg)
            raise RuntimeError(f"Unable to access wireless interfaces: {stderr_msg}")

        return result.stdout

    def scan(self) -> str:
        """
        Executes 'netsh wlan show networks mode=bssid' and returns raw text output.
        """
        command = ["netsh", "wlan", "show", "networks", "mode=bssid"]
        logger.info("Starting Wi-Fi scan via netsh wlan show networks mode=bssid")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                check=False
            )
        except Exception as err:
            logger.error("Failed to execute netsh wlan scan: %s", err)
            raise RuntimeError(f"Wi-Fi scan failed: {err}") from err

        if result.returncode != 0:
            stderr_msg = result.stderr.strip() if result.stderr else "Wi-Fi adapter may be disabled or unavailable."
            logger.error("netsh wlan scan failed with code %d: %s", result.returncode, stderr_msg)
            raise RuntimeError(f"Wi-Fi scan failed: {stderr_msg}")

        logger.info("Wi-Fi scan command completed successfully.")
        return result.stdout