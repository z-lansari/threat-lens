def _has_error(result):
    return isinstance(result, dict) and "error" in result


def _vt_score(stats):
    if not stats or _has_error(stats):
        return None

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    total = malicious + suspicious + harmless + undetected
    if total == 0:
        return None

    return round((malicious + suspicious) / total * 100)


def _abuse_score(data):
    if not data or _has_error(data):
        return None
    return data.get("abuseConfidenceScore")


def _level(score):
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def compute_threat_score(vt_result, abuse_result):
    scores = [
        s for s in (_vt_score(vt_result), _abuse_score(abuse_result))
        if s is not None
    ]

    if not scores:
        return {"threat_score": None, "level": None}

    score = max(scores)
    return {"threat_score": score, "level": _level(score)}