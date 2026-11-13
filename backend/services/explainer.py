"""Plain-language explanations. Uses Gemini when configured, otherwise a template."""
import asyncio
import os
from typing import List

from dotenv import load_dotenv

load_dotenv()

_TEMPLATES = {
    "green": "No major warning signs were found (safety score {score}/100). Still, double-check the details before paying.",
    "yellow": "Some warning signs were found (safety score {score}/100): {sigs}. Verify independently before continuing.",
    "red": "High risk (safety score {score}/100): {sigs}. Do not proceed.",
    "unable_to_verify": "We could not verify this. Please try again or check it manually.",
}


def _fallback(verdict: str, score: int, signals: List[str]) -> str:
    sigs = ", ".join(s.replace("_", " ").lower() for s in signals) or "none"
    return _TEMPLATES.get(verdict, _TEMPLATES["unable_to_verify"]).format(score=score, sigs=sigs)


def _call_gemini(prompt: str) -> str:
    import google.generativeai as genai
    genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
    model = genai.GenerativeModel(os.getenv("GEMINI_MODEL", "gemini-2.0-flash"))
    return (model.generate_content(prompt).text or "").strip()


async def generate_explanation(verdict: str, score: int, signals: List[str]) -> str:
    if not os.getenv("GEMINI_API_KEY"):
        return _fallback(verdict, score, signals)
    prompt = (
        "You are a fraud-safety assistant. In 2 short plain sentences, explain to a non-technical "
        f"user why a scan got verdict '{verdict}' (safety score {score}/100) given these signals: "
        f"{', '.join(signals) or 'none'}. Do not use markdown."
    )
    try:
        text = await asyncio.wait_for(asyncio.to_thread(_call_gemini, prompt), timeout=8)
        return text or _fallback(verdict, score, signals)
    except Exception as e:  # network, quota, bad key, timeout...
        print("EXPLAINER FALLBACK:", type(e).__name__, e)
        return _fallback(verdict, score, signals)
