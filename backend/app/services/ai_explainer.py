"""
AI Explanation Engine — the core differentiator of ScamShield.
Takes structured threat signals and produces plain-English explanations
that non-technical users can understand and act on.
"""
from typing import List, Dict, Any, Optional
from app.core.config import settings

# Graceful import — works even without openai installed during testing
try:
    from openai import AsyncOpenAI
    _openai_available = True
except ImportError:
    _openai_available = False


SYSTEM_PROMPT = """You are ScamShield AI, a cybersecurity assistant that explains online threats to everyday people — including elderly users, students, and people who are not tech-savvy.

Your job is to explain WHY something is suspicious in simple, clear language.

Rules:
- Use simple words. No technical jargon.
- Be direct and honest. Don't sugarcoat real threats.
- Keep the explanation to 2-3 sentences maximum.
- Focus on what the user needs to understand, not technical details.
- Never use words like "heuristic", "TLD", "entropy", "vector", or "payload".
- Write as if explaining to a worried grandparent."""

RECOMMENDATION_PROMPT = """Based on the threat analysis, give ONE clear action the user should take.
Start with an action verb. Keep it to 1-2 sentences. Be specific."""


def _build_analysis_context(
    input_type: str,
    input_preview: str,
    signals: List[Dict[str, Any]],
    risk_score: int,
    risk_level: str,
    threat_categories: List[str],
) -> str:
    signal_descriptions = "\n".join(
        f"- {s['description']}" for s in signals
    ) or "- No specific threats detected"

    categories_str = ", ".join(threat_categories) if threat_categories else "None"

    return f"""
Input type: {input_type}
Preview: {input_preview}
Risk score: {risk_score}/100
Risk level: {risk_level}
Threat categories: {categories_str}

What was detected:
{signal_descriptions}
"""


async def generate_explanation(
    input_type: str,
    input_preview: str,
    signals: List[Dict[str, Any]],
    risk_score: int,
    risk_level: str,
    threat_categories: List[str],
) -> tuple[str, str]:
    """
    Returns (explanation, recommendation) tuple.
    Falls back to rule-based explanation if OpenAI is unavailable.
    """
    if not _openai_available or not settings.OPENAI_API_KEY:
        return _fallback_explanation(risk_level, threat_categories, signals), \
               _fallback_recommendation(risk_level)

    context = _build_analysis_context(
        input_type, input_preview, signals, risk_score, risk_level, threat_categories
    )

    try:
        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

        # Run both calls concurrently for speed
        import asyncio
        explanation_task = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Explain this threat analysis:\n{context}"},
            ],
            max_tokens=120,
            temperature=0.3,
        )
        recommendation_task = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": RECOMMENDATION_PROMPT},
                {"role": "user", "content": f"What should the user do?\n{context}"},
            ],
            max_tokens=80,
            temperature=0.2,
        )

        explanation_resp, recommendation_resp = await asyncio.gather(
            explanation_task, recommendation_task
        )

        explanation = explanation_resp.choices[0].message.content.strip()
        recommendation = recommendation_resp.choices[0].message.content.strip()
        return explanation, recommendation

    except Exception:
        # Never let AI failure break the scan
        return _fallback_explanation(risk_level, threat_categories, signals), \
               _fallback_recommendation(risk_level)


def _fallback_explanation(
    risk_level: str,
    threat_categories: List[str],
    signals: List[Dict[str, Any]],
) -> str:
    """Rule-based fallback when OpenAI is unavailable."""
    if risk_level in ("CRITICAL", "HIGH"):
        if "Brand Impersonation" in threat_categories:
            return ("This appears to be a fake website pretending to be a trusted company. "
                    "Scammers create these to steal your passwords or payment details.")
        if "Credential Harvesting" in threat_categories:
            return ("This message or link is trying to get your personal information like passwords or OTPs. "
                    "No legitimate company will ever ask for these through a link or SMS.")
        if "Fraud / Scam" in threat_categories:
            return ("This looks like a scam. The message uses tricks to make you act quickly "
                    "without thinking, which is a classic sign of fraud.")
        return ("Multiple warning signs were detected. This content shows patterns "
                "commonly used by scammers to trick people.")
    elif risk_level == "MEDIUM":
        return ("Some suspicious patterns were found. While this may not be dangerous, "
                "you should be cautious before clicking any links or sharing information.")
    else:
        if signals:
            return ("A minor concern was detected, but the overall risk is low. "
                    "Always stay alert when clicking links from unknown sources.")
        return "No significant threats were detected. This appears to be safe."


def _fallback_recommendation(risk_level: str) -> str:
    recommendations = {
        "CRITICAL": "Do not click any links or share any information. Delete this message immediately and report it to your bank or the relevant authority.",
        "HIGH": "Avoid clicking any links in this content. If you already did, change your passwords immediately and contact your bank if financial information was shared.",
        "MEDIUM": "Be cautious. Do not enter any personal information and verify the source through official channels before proceeding.",
        "LOW": "This appears safe, but always be careful with links from unknown sources.",
    }
    return recommendations.get(risk_level, "Stay cautious and verify before clicking.")
