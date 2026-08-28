def analyze_security(security: str) -> dict:
    """
    Analyzes normalized wireless security type and returns a dictionary
    containing heuristic score, risk level, and educational description.
    """
    sec = security.upper()

    if sec == "WPA3":
        return {
            "score": 100,
            "level": "LOW",
            "description": "Modern wireless security."
        }

    if sec == "WPA2":
        return {
            "score": 85,
            "level": "LOW",
            "description": "Strong commonly used wireless security."
        }

    if sec == "WPA":
        return {
            "score": 60,
            "level": "MEDIUM",
            "description": "Older WPA security detected."
        }

    if sec == "WEP":
        return {
            "score": 20,
            "level": "HIGH",
            "description": "Legacy and weak wireless security."
        }

    if sec == "OPEN":
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