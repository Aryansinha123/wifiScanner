import logging
from typing import List, Dict, Any
from models.network import Network
from utils.parser import signal_to_dbm

logger = logging.getLogger(__name__)


class SimulationManager:
    """
    Offline Simulation & Demo Mode manager.
    Generates synthetic network observations for testing monitoring, risk,
    and anomaly detection without relying on real Wi-Fi changes.
    THIS IS STRICTLY BENIGN / PASSIVE TEST DATA GENERATION.
    """

    def __init__(self):
        self.active_scenario: str = "STABLE_ENVIRONMENT"
        self.simulation_step: int = 0

    def get_available_scenarios(self) -> List[Dict[str, str]]:
        return [
            {"id": "STABLE_ENVIRONMENT", "name": "Stable Environment", "desc": "5 steady networks with consistent parameters."},
            {"id": "NEW_NETWORK_APPEARED", "name": "New Network Appearance", "desc": "A new previously unseen AP appears in scan."},
            {"id": "NETWORK_DISAPPEARED", "name": "Network Disappeared", "desc": "An active network is absent from scan passes."},
            {"id": "SECURITY_DOWNGRADE_SCENARIO", "name": "Security Downgrade", "desc": "A network security shifts from WPA2 to OPEN."},
            {"id": "SECURITY_UPGRADE_SCENARIO", "name": "Security Upgrade", "desc": "An OPEN network security shifts to WPA2."},
            {"id": "CHANNEL_CHANGE_SCENARIO", "name": "Channel Shift", "desc": "An AP shifts from Channel 1 to Channel 6."},
            {"id": "SIGNAL_ANOMALY_SCENARIO", "name": "Signal Fluctuation", "desc": "A network experiences an abrupt 40% signal jump."},
            {"id": "BASELINE_DEVIATION_SCENARIO", "name": "Baseline Deviation", "desc": "Unseen open network appears in baseline environment."}
        ]

    def set_scenario(self, scenario_id: str):
        self.active_scenario = scenario_id
        self.simulation_step = 0
        logger.info("Simulation scenario set to '%s'.", scenario_id)

    def generate_simulated_networks(self) -> List[Network]:

        """
        Generates simulated Network objects according to the active scenario.
        """
        self.simulation_step += 1

        base_networks = [
            Network(
                ssid="Corporate_HQ",
                bssid="00:11:22:33:44:55",
                signal_percent=85,
                signal_dbm=signal_to_dbm(85),
                channel=6,
                band="2.4 GHz",
                security="WPA2",
                encryption="CCMP",
                radio_type="802.11n",
                vendor="Cisco Systems"
            ),
            Network(
                ssid="Guest_Wifi",
                bssid="00:11:22:33:44:56",
                signal_percent=70,
                signal_dbm=signal_to_dbm(70),
                channel=11,
                band="2.4 GHz",
                security="OPEN",
                encryption="NONE",
                radio_type="802.11g",
                vendor="Cisco Systems"
            ),
            Network(
                ssid="Exec_5G",
                bssid="00:11:22:33:44:57",
                signal_percent=92,
                signal_dbm=signal_to_dbm(92),
                channel=36,
                band="5 GHz",
                security="WPA3",
                encryption="CCMP",
                radio_type="802.11ac",
                vendor="Aruba Networks"
            ),
            Network(
                ssid="IoT_Devices",
                bssid="00:26:5A:11:22:33",
                signal_percent=60,
                signal_dbm=signal_to_dbm(60),
                channel=1,
                band="2.4 GHz",
                security="WPA2",
                encryption="TKIP",
                radio_type="802.11n",
                vendor="D-Link Corporation"
            )
        ]

        sc = self.active_scenario

        if sc == "STABLE_ENVIRONMENT":
            return base_networks

        elif sc == "NEW_NETWORK_APPEARED":
            result = list(base_networks)
            if self.simulation_step >= 2:
                result.append(Network(
                    ssid="Visitor_Hotspot",
                    bssid="AA:BB:CC:11:22:33",
                    signal_percent=65,
                    signal_dbm=signal_to_dbm(65),
                    channel=6,
                    band="2.4 GHz",
                    security="WPA2",
                    encryption="CCMP",
                    radio_type="802.11n",
                    vendor="TP-Link Technologies"
                ))
            return result

        elif sc == "NETWORK_DISAPPEARED":
            result = list(base_networks)
            if self.simulation_step >= 2:
                # Omit IoT_Devices network
                result = [n for n in result if n.bssid != "00:26:5A:11:22:33"]
            return result

        elif sc == "SECURITY_DOWNGRADE_SCENARIO":
            result = list(base_networks)
            if self.simulation_step >= 2:
                # Corporate_HQ downgrades from WPA2 -> OPEN
                for idx, n in enumerate(result):
                    if n.bssid == "00:11:22:33:44:55":
                        result[idx] = Network(
                            ssid="Corporate_HQ",
                            bssid="00:11:22:33:44:55",
                            signal_percent=85,
                            signal_dbm=signal_to_dbm(85),
                            channel=6,
                            band="2.4 GHz",
                            security="OPEN",
                            encryption="NONE",
                            radio_type="802.11n",
                            vendor="Cisco Systems"
                        )
            return result

        elif sc == "SECURITY_UPGRADE_SCENARIO":
            result = list(base_networks)
            if self.simulation_step >= 2:
                # Guest_Wifi upgrades from OPEN -> WPA2
                for idx, n in enumerate(result):
                    if n.bssid == "00:11:22:33:44:56":
                        result[idx] = Network(
                            ssid="Guest_Wifi",
                            bssid="00:11:22:33:44:56",
                            signal_percent=70,
                            signal_dbm=signal_to_dbm(70),
                            channel=11,
                            band="2.4 GHz",
                            security="WPA2",
                            encryption="CCMP",
                            radio_type="802.11g",
                            vendor="Cisco Systems"
                        )
            return result

        elif sc == "CHANNEL_CHANGE_SCENARIO":
            result = list(base_networks)
            if self.simulation_step >= 2:
                # IoT_Devices shifts from Channel 1 to Channel 6
                for idx, n in enumerate(result):
                    if n.bssid == "00:26:5A:11:22:33":
                        result[idx] = Network(
                            ssid="IoT_Devices",
                            bssid="00:26:5A:11:22:33",
                            signal_percent=60,
                            signal_dbm=signal_to_dbm(60),
                            channel=6,
                            band="2.4 GHz",
                            security="WPA2",
                            encryption="TKIP",
                            radio_type="802.11n",
                            vendor="D-Link Corporation"
                        )
            return result

        elif sc == "SIGNAL_ANOMALY_SCENARIO":
            result = list(base_networks)
            if self.simulation_step >= 2:
                # Corporate_HQ jumps signal 85 -> 40
                for idx, n in enumerate(result):
                    if n.bssid == "00:11:22:33:44:55":
                        result[idx] = Network(
                            ssid="Corporate_HQ",
                            bssid="00:11:22:33:44:55",
                            signal_percent=40,
                            signal_dbm=signal_to_dbm(40),
                            channel=6,
                            band="2.4 GHz",
                            security="WPA2",
                            encryption="CCMP",
                            radio_type="802.11n",
                            vendor="Cisco Systems"
                        )
            return result

        elif sc == "BASELINE_DEVIATION_SCENARIO":
            result = list(base_networks)
            if self.simulation_step >= 2:
                result.append(Network(
                    ssid="Unverified_AP",
                    bssid="DE:AD:BE:EF:00:01",
                    signal_percent=88,
                    signal_dbm=signal_to_dbm(88),
                    channel=1,
                    band="2.4 GHz",
                    security="OPEN",
                    encryption="NONE",
                    radio_type="802.11n",
                    vendor="Unknown Vendor"
                ))
            return result

        return base_networks
