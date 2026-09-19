from typing import Dict, Any
from security.risk_engine import MultiFactorRiskEngine
from security.configuration_analyzer import ConfigurationAnalyzer


def analyze_security(security: str) -> dict:
    """
    Analyzes normalized wireless security type and returns a dictionary
    containing heuristic score, risk level, and educational description.
    Maintains 100% backward compatibility with Phase 1 signature.
    """
    sec = security.upper()

    if sec == "WPA3":
        return {
            "score": 100,
            "level": "LOW",
            "description": "Modern wireless authentication with strong security characteristics."
        }

    if sec == "WPA2":
        return {
            "score": 85,
            "level": "LOW",
            "description": "Commonly used wireless security configuration."
        }

    if sec == "WPA":
        return {
            "score": 60,
            "level": "MEDIUM",
            "description": "Older wireless security configuration."
        }

    if sec == "WEP":
        return {
            "score": 20,
            "level": "HIGH",
            "description": "Legacy wireless security with known weaknesses."
        }

    if sec == "OPEN":
        return {
            "score": 0,
            "level": "CRITICAL",
            "description": "No wireless authentication or encryption was detected."
        }

    return {
        "score": 50,
        "level": "UNKNOWN",
        "description": "Security information could not be determined."
    }