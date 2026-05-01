# insight_engine.py
# Uses Ollama (local) for narrative generation.
# No API key, no rate limits, no internet required.
# Run: ollama pull mistral   (once, to download the model)

import json
import urllib.request


OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL      = "mistral"

SYSTEM_PROMPT = (
    "You are a SOC analyst. Given user behavior data, write a 2-3 line plain English "
    "summary of what is happening and what to do next. "
    "No headers, no bullet points, no sections. "
    "Write like you are briefing a colleague verbally. "
    "Be direct and specific. Maximum 60 words."
)


def _call_ollama(prompt: str) -> str:
    payload = json.dumps({
        "model" : MODEL,
        "prompt": f"{SYSTEM_PROMPT}\n\n{prompt}",
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_predict": 1000,
        }
    }).encode("utf-8")

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode())
            return data["response"]

    except urllib.error.URLError:
        return (
            "[ERROR] Ollama is not running. "
            "Start it with: ollama serve"
        )
    except Exception as e:
        return f"[ERROR] {e}"


def _build_prompt(pattern_data: dict) -> str:
    user     = pattern_data["user"]
    ctx      = pattern_data["risk_context"]
    patterns = pattern_data["patterns_detected"]
    timeline = pattern_data["timeline"]

    pattern_text = ""
    if patterns:
        for p in patterns:
            pattern_text += (
                f"\n- [{p['severity']}] {p['name']}: {p['description']}\n"
                f"  Evidence: {'; '.join(p['evidence'])}\n"
            )
    else:
        pattern_text = "\n- No named attack patterns detected.\n"

    recent        = timeline[-20:]
    timeline_text = "\n".join(
        f"  [{e['session_id']}] {e['action']}" for e in recent
    )

    return f"""
USER UNDER ANALYSIS: {user}

RISK PROFILE:
- Normalized risk score: {ctx.get('normalized_risk')}% ({ctx.get('risk_level')})
- ML verdict: {ctx.get('ml_flag')} (anomaly score: {ctx.get('ml_anomaly_score')})
- Rule engine verdict: {ctx.get('rule_flag')}
- Final system verdict: {ctx.get('final_verdict')}
- Total sessions analyzed: {pattern_data.get('session_count')}

DETECTED ATTACK PATTERNS:
{pattern_text}

RECENT ACTIVITY TIMELINE (last 20 events):
{timeline_text}

Write a threat assessment for this user.
""".strip()


def generate_insight(pattern_data: dict) -> dict:
    user     = pattern_data["user"]
    patterns = pattern_data["patterns_detected"]

    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    highest  = max(
        (p["severity"] for p in patterns),
        key=lambda s: sev_rank.get(s, 0),
        default="NONE"
    )

    verdict = pattern_data["risk_context"].get("final_verdict", "NORMAL")
    if not patterns and verdict == "NORMAL":
        return {
            "user"            : user,
            "insight"         : "No suspicious patterns detected. User behavior appears normal.",
            "pattern_count"   : 0,
            "highest_severity": "NONE",
        }

    prompt  = _build_prompt(pattern_data)
    insight = _call_ollama(prompt)

    return {
        "user"            : user,
        "insight"         : insight,
        "pattern_count"   : len(patterns),
        "highest_severity": highest,
    }


def run_insights(all_pattern_data: list) -> dict:
    results = {}
    total   = len(all_pattern_data)

    needs_api = [pd for pd in all_pattern_data if pd["patterns_detected"] or
                 pd["risk_context"].get("final_verdict") == "ANOMALY"]
    skip_api  = [pd for pd in all_pattern_data if pd not in needs_api]

    for pd in skip_api:
        results[pd["user"]] = {
            "user"            : pd["user"],
            "insight"         : "No suspicious patterns detected. User behavior appears normal.",
            "pattern_count"   : 0,
            "highest_severity": "NONE",
        }

    flagged = len(needs_api)
    print(f"[Insight] {len(skip_api)} clean users skipped, {flagged} flagged users queued")
    print(f"[Insight] Using local Ollama ({MODEL}) — no rate limits")

    for i, pd in enumerate(needs_api):
        user = pd["user"]
        print(f"[Insight] Generating narrative {i+1}/{flagged}: {user}...")
        results[user] = generate_insight(pd)
        print(f"[Insight] Done: {user}")

    return results