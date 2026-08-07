"""
Basilisk model registry — single source of truth for provider → model mappings.

Used by LiteLLMAdapter, desktop_backend, and CLI for consistent model lists.
"""

from __future__ import annotations

# Default model per provider
DEFAULT_MODELS: dict[str, str] = {
    "openai": "gpt-4",
    "anthropic": "claude-3-5-sonnet-20241022",
    "google": "gemini/gemini-2.0-flash",
    "azure": "azure/gpt-4",
    "ollama": "ollama/llama3.1",
    "bedrock": "bedrock/anthropic.claude-3-sonnet",
    "github": "gpt-4o-mini",
    "nvidia": "openai/gpt-oss-20b",
}

# Full model suggestions per provider (for UI dropdowns and CLI help)
MODEL_SUGGESTIONS: dict[str, list[str]] = {
    "openai": ["gpt-4", "gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"],
    "anthropic": [
        "claude-3-5-sonnet-20241022", "claude-3-opus-20240229",
        "claude-3-haiku-20240307",
    ],
    "google": ["gemini/gemini-2.0-flash", "gemini/gemini-1.5-pro"],
    "azure": ["azure/gpt-4", "azure/gpt-35-turbo"],
    "xai": ["grok-beta", "grok-2", "grok-2-1212"],
    "groq": [
        "llama-3.1-8b-instant", "llama-3.3-70b-versatile",
        "mixtral-8x7b-32768",
    ],
    "github": [
        "gpt-4o-mini", "gpt-4o", "gpt-4.1-mini", "gpt-4.1", "gpt-4.1-nano",
        "o3-mini", "o4-mini", "gpt-5-nano", "gpt-5-mini",
        "DeepSeek-R1", "DeepSeek-V3-0324",
        "Meta-Llama-3.3-70B-Instruct", "Llama-4-Scout-17B-16E-Instruct",
        "Mistral-Small-3.1", "Codestral-25.01",
        "Phi-4", "Phi-4-mini-reasoning",
        "Cohere-command-a", "Grok-3-Mini",
    ],
    "ollama": ["ollama/llama3.1", "ollama/mistral", "ollama/codellama"],
    "bedrock": [
        "bedrock/anthropic.claude-3-sonnet", "bedrock/meta.llama3",
    ],
    "nvidia": ["openai/gpt-oss-20b"],
}

# Provider name → required environment variable
PROVIDER_ENV_VARS: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GOOGLE_API_KEY",
    "azure": "AZURE_API_KEY",
    "xai": "XAI_API_KEY",
    "groq": "GROQ_API_KEY",
    "github": "GH_MODELS_TOKEN",
    "bedrock": "AWS_ACCESS_KEY_ID",
    "nvidia": "NVIDIA_API_KEY",
}
