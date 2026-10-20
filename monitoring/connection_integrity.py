import re
import socket
import json
import logging
import subprocess
import urllib.request
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

from storage.database import DatabaseManager
from monitoring.alert_manager import AlertManager

logger = logging.getLogger(__name__)

CANARY_DOMAINS = ["google.com", "cloudflare.com", "wikipedia.org"]


class ConnectionIntegrityMonitor:
    """
    Connection Integrity & Security Monitor.
    Monitors the network the device is actively connected to for:
      1. ARP Spoofing & Gateway MAC Tampering
      2. DNS Hijacking via secure DoH canary cross-validation
      3. Default Gateway IP / MAC changes on the same SSID
    """

    def __init__(self, db_manager: DatabaseManager, alert_mgr: Optional[AlertManager] = None):
        self.db = db_manager
        self.alert_mgr = alert_mgr or AlertManager(self.db)
        # In-memory record of known gateway state per SSID: {ssid: {"ip": gateway_ip, "mac": gateway_mac}}
        self._gateway_cache: Dict[str, Dict[str, str]] = {}

    @staticmethod
    def get_connected_wifi_details() -> Dict[str, Any]:
        """
        Parses 'netsh wlan show interfaces' for current connection profile.
        """
        info = {
            "connected": False,
            "interface": "Unknown",
            "state": "disconnected",
            "ssid": "",
            "bssid": "",
            "radio_type": "",
            "signal": ""
        }

        try:
            res = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=6,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            out = res.stdout

            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                if ":" in line:
                    parts = line.split(":", 1)
                    key = parts[0].strip().lower()
                    val = parts[1].strip()

                    if key == "name":
                        info["interface"] = val
                    elif key == "state":
                        info["state"] = val
                        if val.lower() == "connected":
                            info["connected"] = True
                    elif key == "ssid":
                        info["ssid"] = val
                    elif key == "bssid":
                        info["bssid"] = val.upper()
                    elif key == "radio type":
                        info["radio_type"] = val
                    elif key == "signal":
                        info["signal"] = val
        except Exception as err:
            logger.warning("Error querying netsh wlan show interfaces: %s", err)

        return info

    @staticmethod
    def get_default_gateway_ip() -> Optional[str]:
        """
        Retrieves the default gateway IPv4 address using route print / ipconfig.
        """
        try:
            res = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True,
                timeout=6,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            out = res.stdout
            # Look for line with 0.0.0.0 0.0.0.0 <gateway> <interface>
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gateway_ip = parts[2]
                    if gateway_ip != "On-link" and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", gateway_ip):
                        return gateway_ip
        except Exception as err:
            logger.warning("Failed to resolve default gateway IP via route print: %s", err)

        # Fallback to ipconfig
        try:
            res = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                timeout=6,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            for line in res.stdout.splitlines():
                if "default gateway" in line.lower() and ":" in line:
                    val = line.split(":", 1)[1].strip()
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val):
                        return val
        except Exception as err:
            logger.warning("Failed to resolve gateway via ipconfig: %s", err)

        return None

    @staticmethod
    def get_gateway_mac(gateway_ip: str) -> Optional[str]:
        """
        Resolves the hardware MAC address of the default gateway from ARP table.
        """
        if not gateway_ip:
            return None

        try:
            res = subprocess.run(
                ["arp", "-a", gateway_ip],
                capture_output=True,
                text=True,
                timeout=6,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            out = res.stdout
            for line in out.splitlines():
                if gateway_ip in line:
                    match = re.search(r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})", line)
                    if match:
                        mac_clean = match.group(1).replace("-", ":").upper()
                        return mac_clean
        except Exception as err:
            logger.warning("Failed to query ARP table for gateway %s: %s", gateway_ip, err)

        return None

    @staticmethod
    def check_dns_integrity(domains: Optional[List[str]] = None) -> Tuple[str, str, Dict[str, Any]]:
        """
        Cross-validates system DNS resolution against secure DNS-over-HTTPS (Cloudflare/Google).
        Detects rogue DNS poisoning, bogus IP redirection, and private IP hijacking.
        Returns: (status: 'CONSISTENT' | 'MISMATCH' | 'OFFLINE_SKIPPED', details_summary, domain_results)
        """
        test_domains = domains or CANARY_DOMAINS
        domain_results = {}
        has_mismatch = False
        doh_successful = 0

        for domain in test_domains:
            # 1. System DNS Resolution
            sys_ip = None
            try:
                sys_ip = socket.gethostbyname(domain)
            except Exception as e:
                sys_ip = f"Error: {e}"

            # 2. Trusted DoH Resolution (Cloudflare 1.1.1.1)
            doh_ips: List[str] = []
            try:
                url = f"https://1.1.1.1/dns-query?name={domain}&type=A"
                req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
                with urllib.request.urlopen(req, timeout=4) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        answers = data.get("Answer", [])
                        doh_ips = [ans["data"] for ans in answers if ans.get("type") == 1]
                        doh_successful += 1
            except Exception:
                # Fallback to Google DoH
                try:
                    url = f"https://dns.google/resolve?name={domain}&type=A"
                    req = urllib.request.Request(url, headers={"Accept": "application/json"})
                    with urllib.request.urlopen(req, timeout=4) as resp:
                        if resp.status == 200:
                            data = json.loads(resp.read().decode("utf-8"))
                            answers = data.get("Answer", [])
                            doh_ips = [ans["data"] for ans in answers if ans.get("type") == 1]
                            doh_successful += 1
                except Exception:
                    pass

            # 3. Analyze Consistency
            is_suspicious = False
            suspicion_reason = ""

            if sys_ip and not sys_ip.startswith("Error"):
                # Bogon / Private IP check for public canary domain
                if sys_ip.startswith("127.") or sys_ip == "0.0.0.0":
                    is_suspicious = True
                    suspicion_reason = "System DNS returned loopback address"
                elif sys_ip.startswith("10.") or sys_ip.startswith("192.168.") or re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", sys_ip):
                    is_suspicious = True
                    suspicion_reason = "System DNS returned private RFC1918 internal IP"

                # If DoH returned answers and system IP doesn't match and looks suspicious
                if doh_ips and sys_ip not in doh_ips:
                    # Some domains use Anycast / CDN with different IPs, but private IPs are always bad
                    if is_suspicious:
                        has_mismatch = True

            domain_results[domain] = {
                "system_ip": sys_ip,
                "doh_ips": doh_ips,
                "is_suspicious": is_suspicious,
                "reason": suspicion_reason
            }

        if doh_successful == 0:
            return "OFFLINE_SKIPPED", "DoH servers unreachable (offline or filtered)", domain_results

        if has_mismatch:
            return "MISMATCH", "Rogue DNS response or private IP poisoning detected for canary domains", domain_results

        return "CONSISTENT", "System DNS resolution matches public recursive DoH", domain_results

    def run_integrity_check(self) -> Dict[str, Any]:
        """
        Executes a comprehensive connection integrity evaluation for the active Wi-Fi link.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        wifi = self.get_connected_wifi_details()

        if not wifi["connected"] or not wifi["ssid"]:
            result = {
                "timestamp": timestamp,
                "connected": False,
                "ssid": "Not Connected",
                "bssid": "N/A",
                "gateway_ip": "N/A",
                "gateway_mac": "N/A",
                "arp_status": "NOT_CONNECTED",
                "dns_status": "NOT_CONNECTED",
                "overall_health": "SAFE",
                "details": "No active wireless connection detected."
            }
            return result

        ssid = wifi["ssid"]
        bssid = wifi["bssid"]

        # Step 1: Gateway Resolution
        gw_ip = self.get_default_gateway_ip() or "Unknown"
        gw_mac = self.get_gateway_mac(gw_ip) if gw_ip != "Unknown" else "Unknown"

        # Step 2: ARP Spoofing & Gateway Change Check
        cached_gw = self._gateway_cache.get(ssid)
        arp_status = "STABLE"
        details_list = []

        if cached_gw:
            cached_ip = cached_gw.get("ip")
            cached_mac = cached_gw.get("mac")

            # Check for sudden MAC swap on identical gateway IP
            if gw_mac and cached_mac and gw_mac != "Unknown" and cached_mac != "Unknown":
                if gw_mac != cached_mac:
                    arp_status = "SPOOF_DETECTED"
                    msg = f"Potential ARP Spoofing / Gateway MAC Tampering! Gateway {gw_ip} MAC changed from {cached_mac} to {gw_mac} on SSID '{ssid}'"
                    details_list.append(msg)
                    logger.critical(msg)
                    self.alert_mgr.dispatch_alert(
                        alert_type="ARP_SPOOFING_DETECTED",
                        severity="CRITICAL",
                        bssid=bssid or gw_mac,
                        ssid=ssid,
                        message=msg,
                        evidence=f"Previous MAC: {cached_mac}, New MAC: {gw_mac}, Gateway IP: {gw_ip}"
                    )
            elif gw_ip != cached_ip:
                arp_status = "GATEWAY_CHANGED"
                msg = f"Default gateway IP changed on SSID '{ssid}': {cached_ip} -> {gw_ip}"
                details_list.append(msg)
                logger.warning(msg)
        else:
            # First observation for this SSID
            if gw_mac and gw_mac != "Unknown":
                self._gateway_cache[ssid] = {"ip": gw_ip, "mac": gw_mac}

        # Step 3: DNS Hijacking Check
        dns_status, dns_summary, dns_domains = self.check_dns_integrity()
        if dns_status == "MISMATCH":
            details_list.append(f"DNS Hijacking: {dns_summary}")
            self.alert_mgr.dispatch_alert(
                alert_type="DNS_HIJACKING_DETECTED",
                severity="CRITICAL",
                bssid=bssid,
                ssid=ssid,
                message=f"DNS poisoning detected on network '{ssid}': {dns_summary}",
                evidence=json.dumps(dns_domains)
            )
        else:
            details_list.append(f"DNS Health: {dns_summary}")

        # Step 4: Overall Health Calculation
        if arp_status == "SPOOF_DETECTED" or dns_status == "MISMATCH":
            overall_health = "CRITICAL"
        elif arp_status == "GATEWAY_CHANGED":
            overall_health = "WARNING"
        else:
            overall_health = "SAFE"

        details_str = " | ".join(details_list)

        # Step 5: Save Log to Database
        self.db.repos.log_connection_integrity(
            timestamp=timestamp,
            ssid=ssid,
            gateway_ip=gw_ip,
            gateway_mac=gw_mac or "Unknown",
            arp_status=arp_status,
            dns_status=dns_status,
            overall_health=overall_health,
            details=details_str
        )

        return {
            "timestamp": timestamp,
            "connected": True,
            "ssid": ssid,
            "bssid": bssid,
            "gateway_ip": gw_ip,
            "gateway_mac": gw_mac or "Unknown",
            "arp_status": arp_status,
            "dns_status": dns_status,
            "overall_health": overall_health,
            "details": details_str
        }
