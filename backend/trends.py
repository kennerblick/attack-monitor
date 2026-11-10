"""Trend, Erwartungswert und 24-h-Prognose aus stündlichen Zählungen (deterministisch, ohne LLM).

Erwartung je Tagesstunde (UTC) = Median derselben Stunde an den letzten 7 Tagen, Band = Median ± 2·σ mit
σ = 1,4826·MAD. Median/MAD statt Mittelwert/Standardabweichung, weil einzelne Wellen sonst die Erwartung verzerren.
Prognose = Erwartung × Niveau der letzten 6 h; das Niveau klingt über den Horizont auf 1 ab (Wellen ebben ab).
"""
HOUR = 3600
DAYS = 7
LEVEL_HOURS = 6
WAVE_MIN = 50  # Stunden mit weniger Events gelten nie als Ausreißer


def hourly_counts(store, now):
    """Stundennummer (ts // 3600) -> Anzahl Events der letzten 7 Tage plus laufende Stunde."""
    start = (int(now) // HOUR - DAYS * 24) * HOUR
    return dict(store.query("SELECT CAST(ts/3600 AS INTEGER) h, COUNT(*) FROM events WHERE ts>=? GROUP BY h", (start,)))


def median(values):
    s = sorted(values)
    n = len(s)
    if not n:
        return 0
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def baseline(counts, cur_hour):
    """Tagesstunde -> (Median, σ) aus den vollen Stunden der 7 Tage vor cur_hour."""
    by_hour = {}
    for h in range(cur_hour - DAYS * 24, cur_hour):
        by_hour.setdefault(h % 24, []).append(counts.get(h, 0))
    out = {}
    for hod, values in by_hour.items():
        m = median(values)
        out[hod] = (m, 1.4826 * median([abs(v - m) for v in values]))
    return out


def _point(t, exp, sigma, factor=1.0):
    return {"t": t, "exp": round(exp * factor, 1), "lo": round(max(0.0, exp - 2 * sigma) * factor, 1),
            "hi": round((exp + 2 * sigma) * factor, 1)}


def compute(counts, now):
    cur = int(now) // HOUR
    base = baseline(counts, cur)
    recent = range(cur - LEVEL_HOURS, cur)
    actual = sum(counts.get(h, 0) for h in recent)
    expected = sum(base[h % 24][0] for h in recent)
    level = min(2.0, max(0.5, actual / expected)) if expected else 1.0

    history, anomalies = [], []
    for h in range(cur - 24, cur):
        n = counts.get(h, 0)
        m, s = base[h % 24]
        p = _point(h * HOUR, m, s)
        history.append({**p, "n": n})
        if n >= WAVE_MIN and n > p["hi"] and n > 2 * m:
            anomalies.append({"t": h * HOUR, "n": n, "exp": p["exp"], "pct": round((n / m - 1) * 100) if m else None})

    # laufende Stunde und die 23 folgenden; Niveau klingt linear auf 1 ab
    forecast = [_point(h * HOUR, *base[h % 24], factor=level ** (1 - i / 24)) for i, h in enumerate(range(cur, cur + 24))]
    elapsed = max(0.1, (now - cur * HOUR) / HOUR)
    so_far = counts.get(cur, 0)
    return {
        "level": round(level, 2),
        "deviation": round((actual / expected - 1) * 100) if expected else None,  # letzte 6 h vs. Erwartung, in %
        "current": {"t": cur * HOUR, "n": so_far, "pace": round(so_far / elapsed), "exp": forecast[0]["exp"]},
        "next24": round(sum(p["exp"] for p in forecast)),
        "last24": sum(p["n"] for p in history),
        "history": history, "forecast": forecast, "anomalies": anomalies,
    }
