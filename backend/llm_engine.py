"""
AIGIS LLM Gateway & Autonomous Agentic Reasoning Engine
Hỗ trợ đa dạng các mô hình MIỄN PHÍ (Free Tiers):
1. Google Gemini 1.5/2.0 Flash (Free Tier từ Google AI Studio - 15 RPM / 1M TPM miễn phí)
2. Groq Cloud (Free Tier - Llama 3.3 70B & DeepSeek R1 siêu tốc)
3. OpenRouter Free Tier (:free models)
4. GitHub Models (Free Personal Access Token)
5. Autonomous Heuristic Engine (100% Free, Offline, Zero-Setup, chạy trực tiếp)
"""

import os
import re
import json
import time
from urllib.parse import urlparse
import httpx
from typing import Dict, Any, List, Optional

ALLOWED_PROVIDERS = {"gemini", "groq", "openrouter", "openai", "cerebras", "sambanova", "github", "ollama", "heuristic"}
PROVIDER_KEY_ENV = {
    "gemini": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "openai": "OPENAI_API_KEY",
    "cerebras": "CEREBRAS_API_KEY",
    "sambanova": "SAMBANOVA_API_KEY",
    "github": "GITHUB_TOKEN",
}
DEFAULT_BASE_URLS = {
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "openai": "https://api.openai.com/v1",
    "cerebras": "https://api.cerebras.ai/v1",
    "sambanova": "https://api.sambanova.ai/v1",
    "github": "https://models.inference.ai.azure.com",
    "ollama": "http://localhost:11434/v1",
    "gemini": "",
    "heuristic": ""
}
DEFAULT_MODELS = {
    "gemini": "gemini-1.5-flash-latest",
    "groq": "llama-3.3-70b-versatile",
    "openrouter": "meta-llama/llama-3.3-70b-instruct:free",
    "openai": "gpt-4o-mini",
    "cerebras": "llama-3.3-70b",
    "sambanova": "Meta-Llama-3.3-70B-Instruct",
    "github": "gpt-4o-mini",
    "ollama": "llama3.2",
    "heuristic": "heuristic-reasoner-v1"
}
ALLOWED_HOSTS = {
    "groq": {"api.groq.com"},
    "openrouter": {"openrouter.ai"},
    "openai": {"api.openai.com"},
    "cerebras": {"api.cerebras.ai"},
    "sambanova": {"api.sambanova.ai"},
    "github": {"models.inference.ai.azure.com"},
    "ollama": {"localhost", "127.0.0.1", "::1"},
    "gemini": {"generativelanguage.googleapis.com"},
    "heuristic": set()
}

def _is_allowed_base_url(provider: str, url: str) -> bool:
    """Allow only the provider's official API host (or loopback for local Ollama)."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if not parsed.hostname:
        return False
    if provider == "ollama":
        return parsed.scheme in ("http", "https") and parsed.hostname in ALLOWED_HOSTS["ollama"]
    return parsed.scheme == "https" and parsed.hostname in ALLOWED_HOSTS.get(provider, set())

def normalize_gemini_model_name(name: str) -> str:
    """Chuẩn hóa tên model Gemini thành định dạng API hợp lệ của Google"""
    if not name:
        return "gemini-1.5-flash-latest"
    clean = name.strip().lower().replace("models/", "")
    clean = re.sub(r"\s+", "-", clean)
    if clean in ["gemini-1.5-flash", "gemini-flash", "flash"]:
        return "gemini-1.5-flash-latest"
    if clean in ["gemini-2.0-flash", "gemini-2-flash"]:
        return "gemini-2.0-flash"
    if clean in ["gemini-pro", "gemini-1.5-pro", "pro"]:
        return "gemini-1.5-pro-latest"
    return clean

class LLMEngine:
    def __init__(self):
        # Đọc cấu hình từ môi trường hoặc khởi tạo mặc định
        env_provider = (os.getenv("AIGIS_LLM_PROVIDER", "heuristic") or "heuristic").strip().lower()
        self.provider = env_provider if env_provider in ALLOWED_PROVIDERS else "heuristic"
        # Never send another provider's credential to the selected provider.
        key_env = PROVIDER_KEY_ENV.get(self.provider)
        self.api_key = os.getenv(key_env, "").strip() if key_env else ""
        self.last_call_error: Optional[str] = None
        self.last_call_latency_ms: Optional[float] = None
        self.last_call_success: bool = False
        self.last_raw_response: str = ""
        self._cached_gemini_models: List[str] = []

        self.model_name = DEFAULT_MODELS[self.provider]
        self.base_url = DEFAULT_BASE_URLS.get(self.provider, "")

    def configure(self, provider: str, api_key: str = "", model_name: str = "", base_url: str = ""):
        # Validate provider against safe allowlist
        clean_provider = (provider or "heuristic").strip().lower()
        if clean_provider not in ALLOWED_PROVIDERS:
            clean_provider = "heuristic"

        # Nếu đổi sang provider khác mà không truyền api_key mới, xóa key cũ để chống đánh cắp key qua base_url
        if clean_provider != self.provider and not api_key:
            self.api_key = ""
        elif api_key:
            self.api_key = api_key.strip()
            self._cached_gemini_models = []

        self.provider = clean_provider

        model_name = (model_name or "").strip()
        # A model name left over from another provider's default (e.g. the UI still showing
        # "heuristic-reasoner-v1" after switching to Groq) is treated as "use the default".
        if model_name and any(model_name == m for p, m in DEFAULT_MODELS.items() if p != clean_provider):
            model_name = ""
        if clean_provider == "heuristic":
            model_name = ""

        if model_name:
            if clean_provider == "gemini":
                self.model_name = normalize_gemini_model_name(model_name)
            else:
                self.model_name = model_name
        else:
            self.model_name = DEFAULT_MODELS[clean_provider]

        # Thiết lập base_url mặc định theo provider
        self.base_url = DEFAULT_BASE_URLS.get(clean_provider, "")

        # Nếu người dùng chỉ định base_url tùy chỉnh: chỉ chấp nhận host chính thức của provider
        base_url_error = None
        if base_url:
            clean_url = base_url.strip().rstrip("/")
            if _is_allowed_base_url(clean_provider, clean_url):
                self.base_url = clean_url
            else:
                base_url_error = (
                    f"Rejected base URL for {clean_provider}: only the provider's official API host is allowed."
                )

        self.last_call_error = base_url_error

    def get_status(self) -> Dict[str, Any]:
        keyed_providers = {"gemini", "groq", "openrouter", "openai", "cerebras", "sambanova", "github"}
        is_connected = (self.provider in keyed_providers and bool(self.api_key)) or self.provider == "ollama"
        return {
            "provider": self.provider,
            "model_name": self.model_name,
            "has_api_key": bool(self.api_key),
            "base_url": self.base_url,
            "mode": "API_CONNECTED" if is_connected else "AUTONOMOUS_HEURISTIC_REACT",
            "is_free_tier": self.provider in ["gemini", "groq", "openrouter", "cerebras", "sambanova", "github", "ollama", "heuristic"],
            "last_error": self.last_call_error,
            "last_latency_ms": self.last_call_latency_ms
        }

    async def list_available_gemini_models(self) -> List[str]:
        """Tự động truy vấn ModelService.ListModels từ Google để tìm các model khả dụng cho API Key này"""
        if not self.api_key:
            return []
        if self._cached_gemini_models:
            return self._cached_gemini_models

        url = "https://generativelanguage.googleapis.com/v1beta/models"
        headers = {"x-goog-api-key": self.api_key}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    models = []
                    for m in data.get("models", []):
                        if "generateContent" in m.get("supportedGenerationMethods", []):
                            clean_name = m.get("name", "").replace("models/", "").strip()
                            if clean_name:
                                models.append(clean_name)
                    if models:
                        self._cached_gemini_models = models
                        return models
                elif resp.status_code in [400, 403]:
                    try:
                        err_json = resp.json()
                        err_msg = err_json.get("error", {}).get("message", resp.text)
                    except Exception:
                        err_msg = resp.text
                    self.last_call_error = f"Gemini API Key Error ({resp.status_code}): {err_msg}"
        except Exception as e:
            self.last_call_error = f"Gemini connection error: {str(e)}"
        return []

    async def test_connection(self) -> Dict[str, Any]:
        """Kiểm tra trực tiếp API key kết nối tới provider"""
        t0 = time.time()
        if self.provider == "heuristic":
            return {
                "success": True,
                "provider": "heuristic",
                "model_name": self.model_name,
                "message": "Autonomous Heuristic Reasoner is active and operational (100% offline).",
                "latency_ms": 0.5
            }
        
        if not self.api_key and self.provider != "ollama":
            return {
                "success": False,
                "provider": self.provider,
                "model_name": self.model_name,
                "error": f"API Key for {self.provider.upper()} is missing. Please enter your API key."
            }

        # Nếu là Gemini, kiểm tra trước với ListModels để phát hiện ngay key không hợp lệ hoặc tìm model tối ưu
        if self.provider == "gemini":
            discovered = await self.list_available_gemini_models()
            if not discovered and self.last_call_error and "API Key Error" in self.last_call_error:
                return {
                    "success": False,
                    "provider": "gemini",
                    "model_name": self.model_name,
                    "error": self.last_call_error,
                    "latency_ms": round((time.time() - t0) * 1000, 2)
                }

        try:
            test_response = await self.call_llm(
                system_prompt="You are a test ping agent. Reply ONLY with the word 'OK'.",
                user_prompt="Ping",
                temperature=0.0
            )
            elapsed = round((time.time() - t0) * 1000, 2)
            if test_response:
                return {
                    "success": True,
                    "provider": self.provider,
                    "model_name": self.model_name,
                    "message": f"Successfully connected to {self.provider.upper()} ({self.model_name})!",
                    "sample_reply": test_response.strip()[:60],
                    "latency_ms": elapsed
                }
            else:
                err = self.last_call_error or f"Failed to get response from {self.provider.upper()}. Please verify API key."
                return {
                    "success": False,
                    "provider": self.provider,
                    "model_name": self.model_name,
                    "error": err,
                    "latency_ms": elapsed
                }
        except Exception as e:
            return {
                "success": False,
                "provider": self.provider,
                "model_name": self.model_name,
                "error": str(e),
                "latency_ms": round((time.time() - t0) * 1000, 2)
            }

    async def call_llm(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        """
        Gọi trực tiếp API của LLM (Gemini / Groq / OpenRouter / OpenAI / Ollama)
        """
        t0 = time.time()
        self.last_call_error = None
        self.last_call_success = False
        try:
            resp = ""
            if self.provider == "gemini" and self.api_key:
                resp = await self._call_gemini(system_prompt, user_prompt, temperature)
            elif self.provider in ["groq", "openrouter", "openai", "cerebras", "sambanova", "github"] and self.api_key:
                resp = await self._call_openai_compatible_with_key(system_prompt, user_prompt, temperature)
            elif self.provider == "ollama":
                resp = await self._call_openai_compatible_no_key(system_prompt, user_prompt, temperature)
            
            elapsed = round((time.time() - t0) * 1000, 2)
            self.last_call_latency_ms = elapsed
            if resp:
                self.last_call_success = True
                self.last_raw_response = resp
                return resp
        except Exception as e:
            self.last_call_error = str(e)
            print(f"[LLMEngine Error] Failed calling {self.provider}: {e}")
        
        return ""

    async def _call_gemini(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        # Chuẩn hóa tên model người dùng nhập
        normalized = normalize_gemini_model_name(self.model_name)

        # 1. Thử truy vấn Google ListModels để tìm danh sách model thực tế được hỗ trợ
        discovered_models = await self.list_available_gemini_models()
        
        candidates = []
        if discovered_models:
            # Nếu người dùng chọn model cụ thể và nó có trong danh sách
            if normalized in discovered_models:
                candidates.append(normalized)
            # Ưu tiên các model flash trong danh sách khám phá được
            for pref in ["gemini-2.0-flash", "gemini-1.5-flash-latest", "gemini-1.5-flash-002", "gemini-1.5-flash-001", "gemini-1.5-flash"]:
                if pref in discovered_models and pref not in candidates:
                    candidates.append(pref)
            for m in discovered_models:
                if "flash" in m and m not in candidates:
                    candidates.append(m)
            for m in discovered_models:
                if m not in candidates:
                    candidates.append(m)

        # Bổ sung danh sách fallback tĩnh
        static_fallbacks = [
            normalized,
            "gemini-1.5-flash-latest",
            "gemini-2.0-flash",
            "gemini-2.0-flash-exp",
            "gemini-1.5-flash-002",
            "gemini-1.5-flash-001",
            "gemini-1.5-flash",
            "gemini-1.5-pro-latest",
            "gemini-pro"
        ]
        for sf in static_fallbacks:
            if sf not in candidates:
                candidates.append(sf)

        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": f"System Context:\n{system_prompt}\n\nTask:\n{user_prompt}"}]}
            ],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": 2048
            }
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            for candidate in candidates:
                for api_ver in ["v1beta", "v1"]:
                    endpoint = f"https://generativelanguage.googleapis.com/{api_ver}/models/{candidate}:generateContent"
                    headers = {"x-goog-api-key": self.api_key, "Content-Type": "application/json"}
                    try:
                        resp = await client.post(endpoint, json=payload, headers=headers)
                        if resp.status_code == 200:
                            data = resp.json()
                            self.model_name = candidate # Ghi nhớ model đã chạy thành công
                            try:
                                return data["candidates"][0]["content"]["parts"][0]["text"]
                            except (KeyError, IndexError) as e:
                                self.last_call_error = f"Gemini response parsing error: {e}"
                                return ""
                        elif resp.status_code == 404:
                            # Model không tồn tại trên phiên bản API này, tiếp tục thử candidate khác
                            continue
                        elif resp.status_code in [400, 403]:
                            try:
                                err_json = resp.json()
                                err_msg = err_json.get("error", {}).get("message", resp.text)
                            except Exception:
                                err_msg = resp.text
                            self.last_call_error = f"Gemini API Error (HTTP {resp.status_code}): {err_msg}"
                            # Nếu lỗi là sai API Key, ngắt ngay lập tức để người dùng biết
                            if "API key not valid" in err_msg or "INVALID_ARGUMENT" in err_msg:
                                return ""
                            continue
                        else:
                            try:
                                err_json = resp.json()
                                err_msg = err_json.get("error", {}).get("message", resp.text)
                            except Exception:
                                err_msg = resp.text
                            self.last_call_error = f"Gemini API Error (HTTP {resp.status_code}): {err_msg}"
                            continue
                    except Exception as e:
                        self.last_call_error = f"Gemini request exception: {str(e)}"
                        continue

            self.last_call_error = (
                f"Gemini API Error: None of the candidate models ({', '.join(candidates[:3])}) were accessible with this API key. "
                "Please verify your API key at https://aistudio.google.com/."
            )
            return ""

    async def _call_openai_compatible_with_key(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        base = self.base_url or DEFAULT_BASE_URLS.get(self.provider, "")
        if not _is_allowed_base_url(self.provider, base):
            self.last_call_error = f"Refusing to send API key to untrusted base URL: {base!r}"
            return ""

        endpoint = f"{base}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": temperature
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(endpoint, json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            else:
                try:
                    err_json = resp.json()
                    err_msg = err_json.get("error", {}).get("message", resp.text)
                except Exception:
                    err_msg = resp.text
                self.last_call_error = f"{self.provider.upper()} API Error (HTTP {resp.status_code}): {err_msg}"
                print(f"[{self.provider.upper()} Error] {resp.status_code}: {err_msg}")
                return ""

    async def _call_openai_compatible_no_key(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        if not _is_allowed_base_url("ollama", self.base_url):
            self.last_call_error = f"Refusing to call untrusted local base URL: {self.base_url!r}"
            return ""
        endpoint = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": temperature
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(endpoint, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            return ""

# Singleton instance
global_llm_engine = LLMEngine()
