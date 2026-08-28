def analyze_security(security: str) -> dict:

    security = security.upper()

    if security == "WPA3":

        return {
            "score": 100,
            "level": "LOW",
            "description": "Modern wireless security."
        }

    if security == "WPA2":

        return {
            "score": 85,
            "level": "LOW",
            "description": "Strong commonly used wireless security."
        }

    if security == "WPA":

        return {
            "score": 60,
            "level": "MEDIUM",
            "description": "Older WPA security detected."
        }

    if security == "WEP":

        return {
            "score": 20,
            "level": "HIGH",
            "description": "Legacy and weak wireless security."
        }

    if security == "OPEN":

        return {
            "score": 0,
            "level": "CRITICAL",
            "description": "Network has no wireless authentication."
        }

    return {
        "score": 50,
        "level": "UNKNOWN",
        "description": "Security configuration could not be determined."
    }