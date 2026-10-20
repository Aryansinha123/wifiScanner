import os
import json
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: Dict[str, Any] = {
    "scan_interval_sec": 30,
    "missing_scan_threshold": 3,
    "signal_change_threshold": 20,
    "auto_monitoring": False,
    "db_path": "data/wifi_scanner.db",
    "reports_dir": "data/reports",
    "exports_dir": "data/exports",
    "simulation_mode": False,
    "theme": "cybersecurity_dark",
    "alert_severity_threshold": "HIGH",
    "alert_cooldown_minutes": 30,
    "alert_toast_enabled": True,
    "alert_telegram_enabled": False,
    "alert_telegram_bot_token": "",
    "alert_telegram_chat_id": "",
    "alert_email_enabled": False,
    "alert_email_smtp_server": "",
    "alert_email_smtp_port": 587,
    "alert_email_username": "",
    "alert_email_password": "",
    "alert_email_recipient": ""
}


class ConfigManager:
    """
    Manages loading and saving application configuration settings in config.json.
    """

    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config: Dict[str, Any] = dict(DEFAULT_CONFIG)
        self.load_config()

    def load_config(self) -> Dict[str, Any]:
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    self.config.update(loaded)
                logger.info("Configuration loaded from %s", self.config_file)
            except Exception as err:
                logger.error("Failed to load config.json: %s", err)
        else:
            self.save_config()
        return self.config

    def save_config(self) -> bool:
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
            logger.info("Configuration saved to %s", self.config_file)
            return True
        except Exception as err:
            logger.error("Failed to save config.json: %s", err)
            return False

    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)

    def set(self, key: str, value: Any):
        self.config[key] = value
        self.save_config()
