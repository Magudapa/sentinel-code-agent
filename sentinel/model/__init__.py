"""Model layer: local-first LLM client with Ollama default and OpenAI-compatible fallback."""

from .client import ModelClient, ModelUnavailableError, extract_llm_fix

__all__ = ["ModelClient", "ModelUnavailableError", "extract_llm_fix"]