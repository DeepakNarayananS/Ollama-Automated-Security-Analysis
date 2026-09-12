import json
from pathlib import Path

import requests


PROJECT_ROOT = Path(__file__).resolve().parent.parent

CONFIG_FILE = PROJECT_ROOT / "config" / "config.json"


def load_config():
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def ask_ollama(prompt):
    config = load_config()

    ollama = config["ollama"]

    payload = {
        "model": ollama["model"],
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": ollama.get("temperature", 0.1)
        }
    }

    response = requests.post(
        ollama["url"],
        json=payload,
        timeout=ollama.get("timeout", 600)
    )

    response.raise_for_status()

    result = response.json()

    if "response" not in result:
        raise RuntimeError(
            "Ollama response did not contain a 'response' field."
        )

    return result["response"]