import httpx

from app.core.config import get_settings

ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


class AiUnavailable(Exception):
    pass


def generate_json(system_prompt: str, user_prompt: str, schema: dict) -> str:
    settings = get_settings()
    if not settings.gemini_api_key:
        raise AiUnavailable("GEMINI_API_KEY is not configured")

    body = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 8192,
            "responseMimeType": "application/json",
            "responseSchema": schema,
        },
    }
    try:
        response = httpx.post(
            ENDPOINT.format(model=settings.gemini_model),
            headers={"x-goog-api-key": settings.gemini_api_key, "Content-Type": "application/json"},
            json=body,
            timeout=settings.gemini_timeout_seconds,
        )
    except httpx.HTTPError as exc:
        raise AiUnavailable(f"Gemini request failed ({type(exc).__name__})") from None

    if response.status_code == 429:
        raise AiUnavailable("Gemini rate limit or quota reached")
    if response.status_code >= 400:
        raise AiUnavailable(f"Gemini returned HTTP {response.status_code}")

    try:
        parts = response.json()["candidates"][0]["content"]["parts"]
        return "".join(part.get("text", "") for part in parts)
    except (KeyError, IndexError, ValueError):
        raise AiUnavailable("Gemini returned an unexpected response") from None