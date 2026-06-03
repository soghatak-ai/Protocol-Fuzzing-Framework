"""
Shared LLM call utility for the agentic pipeline.

All pipeline modules (orchestrator, explorers, synthesizer) import from here
so there are no circular imports with app.py.
"""

import os
import json
import time

from openai import AzureOpenAI


def ai_call(system_prompt: str, user_prompt: str,
            max_tokens: int = 65536, timeout: int = 600) -> tuple[dict, str]:
    """Call Azure OpenAI chat completion. Returns (parsed_json, model_name).

    Reads config from env vars (same ones app.py uses).
    Retries up to 3 times on transient / rate-limit errors.
    """
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
    api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
    api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2025-01-01-preview")
    model = os.environ.get("AZURE_OPENAI_MODEL", "gpt-5")

    if not endpoint or not api_key:
        raise RuntimeError("AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY must be set in .env")

    client = AzureOpenAI(
        azure_endpoint=endpoint,
        api_key=api_key,
        api_version=api_version,
    )

    last_err = None
    for attempt in range(4):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_completion_tokens=max_tokens,
                response_format={"type": "json_object"},
                timeout=timeout,
            )
            raw = response.choices[0].message.content.strip()
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                if "```json" in raw:
                    parsed = json.loads(raw.split("```json")[1].split("```")[0].strip())
                elif "```" in raw:
                    parsed = json.loads(raw.split("```")[1].split("```")[0].strip())
                else:
                    parsed = {"raw_response": raw, "parse_error": True}

            usage = response.usage
            print(f"[LLM] {model} — prompt:{usage.prompt_tokens} comp:{usage.completion_tokens} total:{usage.total_tokens}")
            return parsed, model

        except Exception as e:
            last_err = e
            err_str = str(e)
            if "429" in err_str or "rate" in err_str.lower() or "timeout" in err_str.lower():
                wait = 2 ** attempt
                print(f"[LLM] Retry {attempt+1}/3 after {wait}s — {type(e).__name__}: {e}")
                time.sleep(wait)
            else:
                raise

    raise last_err  # type: ignore[misc]
