# ollama_client.py
import requests
import json

class OllamaClient:
    def __init__(self, model, url):
        self.model = model
        self.url = url

    def chat(self, prompt: str):
        response = requests.post(
            self.url,
            json={
                "model": self.model,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "stream": False,
            },
            timeout=300
        )
        data = response.json()
        return data["message"]["content"]
