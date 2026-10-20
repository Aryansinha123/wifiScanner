import os
import re
import json
import logging
import threading
import subprocess
import urllib.request
import urllib.parse
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

from storage.database import DatabaseManager
from utils.config import ConfigManager

logger = logging.getLogger(__name__)


class AlertManager:
    """
    Real-Time Alert Dispatcher and Deduplication Engine.
    Dispatches security notifications across offline Windows Toast, Telegram Bot,
    and Email with configurable cooldown, severity thresholds, and deduplication.
    """

    SEVERITY_ORDER = {
        "INFO": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    def __init__(self, db_manager: DatabaseManager, config_mgr: Optional[ConfigManager] = None):
        self.db = db_manager
        self.config_mgr = config_mgr or ConfigManager()

    def _get_threshold_level(self) -> int:
        threshold_str = self.config_mgr.get("alert_severity_threshold", "HIGH").upper()
        if threshold_str == "NONE" or threshold_str == "DISABLED":
            return 99
        if "CRITICAL" in threshold_str and "HIGH" not in threshold_str:
            return 4
        if "HIGH" in threshold_str:
            return 3
        if "MEDIUM" in threshold_str:
            return 2
        return 1  # INFO or ALL

    def is_severity_eligible(self, severity: str) -> bool:
        sev_rank = self.SEVERITY_ORDER.get(severity.upper(), 1)
        thresh_rank = self._get_threshold_level()
        return sev_rank >= thresh_rank

    def is_in_cooldown(self, alert_type: str, bssid: str, cooldown_minutes: int) -> bool:
        """
        Deduplication check: Determines if an identical alert for the same BSSID
        was already sent within the cooldown window or was already acknowledged.
        """
        latest = self.db.repos.get_latest_alert_for(alert_type, bssid)
        if not latest:
            return False

        if latest.get("acknowledged") == 1:
            # Alert is already acknowledged by user — suppress repeats
            return True

        last_sent_str = latest.get("last_sent_at") or latest.get("created_at")
        if not last_sent_str:
            return False

        try:
            last_sent_time = datetime.strptime(last_sent_str, "%Y-%m-%d %H:%M:%S")
            cutoff = datetime.now() - timedelta(minutes=cooldown_minutes)
            return last_sent_time > cutoff
        except Exception as err:
            logger.warning("Error parsing alert timestamp: %s", err)
            return False

    def dispatch_alert(
        self,
        alert_type: str,
        severity: str,
        bssid: str,
        ssid: str,
        message: str,
        evidence: str = "",
        force: bool = False
    ) -> bool:
        """
        Processes and dispatches an alert if it meets severity and cooldown criteria.
        Returns True if notification was sent, False if filtered or suppressed.
        """
        sev_upper = severity.upper()
        cooldown_min = int(self.config_mgr.get("alert_cooldown_minutes", 30))

        # 1. Severity Threshold Filtering
        if not force and not self.is_severity_eligible(sev_upper):
            logger.debug("Alert %s (%s) below threshold, skipping dispatch.", alert_type, sev_upper)
            return False

        # 2. Deduplication & Cooldown Check
        if not force and self.is_in_cooldown(alert_type, bssid, cooldown_min):
            logger.debug("Alert %s for %s is within %d min cooldown, skipping duplicate.",
                         alert_type, bssid, cooldown_min)
            return False

        # 3. Persist Alert to Database
        alert_id = self.db.repos.save_alert(
            alert_type=alert_type,
            severity=sev_upper,
            bssid=bssid,
            ssid=ssid,
            message=message,
            evidence=evidence,
            status="NEW",
            last_sent_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        logger.info("Alert recorded [ID %d]: [%s] %s for %s (%s)", alert_id, sev_upper, alert_type, ssid, bssid)

        # 4. Dispatch Asynchronously (Non-blocking)
        thread = threading.Thread(
            target=self._dispatch_channels,
            args=(alert_type, sev_upper, bssid, ssid, message),
            daemon=True
        )
        thread.start()
        return True

    def _dispatch_channels(self, alert_type: str, severity: str, bssid: str, ssid: str, message: str):
        # Channel 1: Windows Toast Notification (Offline)
        if self.config_mgr.get("alert_toast_enabled", True):
            self.send_windows_toast(
                title=f"Wi-Fi Security Alert: {severity}",
                message=f"[{alert_type}] {ssid} ({bssid})\n{message}"
            )

        # Channel 2: Telegram Bot Notification
        if self.config_mgr.get("alert_telegram_enabled", False):
            token = self.config_mgr.get("alert_telegram_bot_token", "").strip()
            chat_id = self.config_mgr.get("alert_telegram_chat_id", "").strip()
            if token and chat_id:
                tele_msg = f"🚨 *Wi-Fi Security Alert: {severity}*\n\n*Type:* `{alert_type}`\n*SSID:* {ssid}\n*BSSID:* `{bssid}`\n*Details:* {message}"
                self.send_telegram_alert(token, chat_id, tele_msg)

        # Channel 3: Email Notification
        if self.config_mgr.get("alert_email_enabled", False):
            self.send_email_alert(
                subject=f"[Wi-Fi Scanner] {severity} Alert: {alert_type} on {ssid}",
                body=f"Wi-Fi Security Platform Alert\n\nSeverity: {severity}\nAlert Type: {alert_type}\nNetwork: {ssid} ({bssid})\nDetails: {message}\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )

    @staticmethod
    def send_windows_toast(title: str, message: str) -> bool:
        """
        Sends an offline native Windows toast notification using PowerShell WinRT API.
        """
        # Escape string values safely for PowerShell
        clean_title = re.sub(r"[\"'\r\n`$]", " ", title).strip()
        clean_msg = re.sub(r"[\"'\r\n`$]", " ", message).strip()

        ps_script = f"""
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null;
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null;
        $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);
        $text = $xml.GetElementsByTagName('text');
        $text[0].AppendChild($xml.CreateTextNode('{clean_title}')) | Out-Null;
        $text[1].AppendChild($xml.CreateTextNode('{clean_msg}')) | Out-Null;
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xml);
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Wi-Fi Security Scanner').Show($toast);
        """

        try:
            subprocess.Popen(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            return True
        except Exception as err:
            logger.warning("Failed to invoke Windows Toast via PowerShell: %s", err)
            return False

    @staticmethod
    def send_telegram_alert(token: str, chat_id: str, text: str) -> bool:
        """
        Sends an alert message to a Telegram Bot chat using Python standard library.
        """
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                return resp.status == 200
        except Exception as err:
            logger.warning("Failed to send Telegram alert: %s", err)
            return False

    def send_email_alert(self, subject: str, body: str) -> bool:
        """
        Sends an email alert using configured SMTP server and Python standard library smtplib.
        """
        server = self.config_mgr.get("alert_email_smtp_server", "").strip()
        port = int(self.config_mgr.get("alert_email_smtp_port", 587))
        user = self.config_mgr.get("alert_email_username", "").strip()
        password = self.config_mgr.get("alert_email_password", "")
        recipient = self.config_mgr.get("alert_email_recipient", "").strip()

        if not server or not recipient:
            return False

        try:
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = user or "wifi-scanner@security.local"
            msg["To"] = recipient

            with smtplib.SMTP(server, port, timeout=10) as smtp:
                smtp.ehlo()
                if smtp.has_extn("STARTTLS"):
                    smtp.starttls()
                    smtp.ehlo()
                if user and password:
                    smtp.login(user, password)
                smtp.send_message(msg)
            return True
        except Exception as err:
            logger.warning("Failed to send Email alert: %s", err)
            return False
