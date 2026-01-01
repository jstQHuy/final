import os
import logging
from typing import Dict, Any
from abc import ABC, abstractmethod

# Typing: LangChain Chat models implement BaseLanguageModel in langchain-core
try:
    from langchain_core.language_models import BaseLanguageModel as BaseLLM  # type: ignore
except Exception:  # pragma: no cover
    try:
        from langchain_core.language_models.base import BaseLanguageModel as BaseLLM  # type: ignore
    except Exception:  # pragma: no cover
        BaseLLM = Any  # fallback typing only

# Optional providers
try:
    from langchain_openai import ChatOpenAI
except ImportError:
    ChatOpenAI = None

try:
    from langchain_deepseek import ChatDeepSeek
except ImportError:
    ChatDeepSeek = None


logger = logging.getLogger(__name__)


class BaseLLMProvider(ABC):
    @abstractmethod
    def create_llm(self, config: Dict[str, Any]) -> BaseLLM:
        raise NotImplementedError

    @abstractmethod
    def validate_config(self, config: Dict[str, Any]) -> bool:
        raise NotImplementedError


class OpenAIProvider(BaseLLMProvider):
    def validate_config(self, config: Dict[str, Any]) -> bool:
        return bool(config.get("api_key")) and bool(config.get("model"))

    def create_llm(self, config: Dict[str, Any]) -> BaseLLM:
        if ChatOpenAI is None:
            raise ImportError(
                "Missing dependency: langchain-openai. "
                "Install it with: python -m pip install 'langchain-openai<1.0.0'"
            )

        if not self.validate_config(config):
            raise ValueError("OpenAIProvider config must include: api_key, model")

        # Do NOT try to pass api_key/openai_api_key as a constructor param.
        # Different versions may not expose these in the signature.
        os.environ["OPENAI_API_KEY"] = str(config["api_key"])

        base_kwargs: Dict[str, Any] = {
            "temperature": config.get("temperature", 0),
            "streaming": config.get("streaming", False),
            "timeout": config.get("timeout", 30),
            "max_retries": config.get("max_retries", 2),
        }

        if config.get("max_tokens") is not None:
            base_kwargs["max_tokens"] = config["max_tokens"]

        # Some versions accept model=..., others use model_name=...
        last_err: Exception | None = None
        for model_key in ("model", "model_name"):
            try:
                kwargs = dict(base_kwargs)
                kwargs[model_key] = config["model"]
                # Remove None values to avoid unexpected kwargs issues
                kwargs = {k: v for k, v in kwargs.items() if v is not None}
                return ChatOpenAI(**kwargs)
            except TypeError as e:
                last_err = e

        raise RuntimeError(
            "Failed to initialize ChatOpenAI. "
            f"Tried passing model via 'model' and 'model_name'. Last error: {last_err}"
        )


class DeepSeekProvider(BaseLLMProvider):
    def validate_config(self, config: Dict[str, Any]) -> bool:
        return bool(config.get("api_key")) and bool(config.get("model"))

    def create_llm(self, config: Dict[str, Any]) -> BaseLLM:
        if ChatDeepSeek is None:
            raise ImportError(
                "Missing dependency: langchain-deepseek. "
                "You selected provider='deepseek' but the package is not installed.\n"
                "If you do NOT use DeepSeek, keep provider='openai' and you do not need this package.\n"
                "If you DO use DeepSeek, install: python -m pip install langchain-deepseek"
            )

        if not self.validate_config(config):
            raise ValueError("DeepSeekProvider config must include: api_key, model")

        kwargs: Dict[str, Any] = {
            "api_key": config["api_key"],
            "model": config["model"],
            "temperature": config.get("temperature", 0),
            "max_tokens": config.get("max_tokens"),
            "streaming": config.get("streaming", False),
            "timeout": config.get("timeout", 30),
        }
        kwargs = {k: v for k, v in kwargs.items() if v is not None}

        return ChatDeepSeek(**kwargs)


class LLMFactory:
    _providers = {
        "openai": OpenAIProvider(),
        "deepseek": DeepSeekProvider(),
    }

    @classmethod
    def create_llm(cls, provider: str, config: Dict[str, Any]) -> BaseLLM:
        provider = (provider or "openai").lower().strip()
        if provider not in cls._providers:
            raise ValueError(f"Unsupported provider: {provider}")

        prov = cls._providers[provider]
        if not prov.validate_config(config):
            raise ValueError(
                f"Invalid config for provider '{provider}'. Required keys: api_key, model"
            )

        return prov.create_llm(config)


class LLMManager:
    def __init__(self):
        self._llms: Dict[str, BaseLLM] = {}
        self._configs: Dict[str, Dict[str, Any]] = {}

    def create_llm(self, name: str, provider: str, config: Dict[str, Any]) -> BaseLLM:
        llm = LLMFactory.create_llm(provider, config)
        self._llms[name] = llm
        self._configs[name] = {"provider": provider, "config": config}
        return llm

    def get_llm(self, name: str):
        return self._llms.get(name)

    def get_config(self, name: str):
        return self._configs.get(name)


llm_manager = LLMManager()


def create_llm_from_config(config: Dict[str, Any]) -> BaseLLM:
    """
    Expected config format (example):
    {
      "provider": "openai",
      "name": "default",
      "api_key": "...",
      "model": "gpt-4o-mini",
      "temperature": 0,
      "timeout": 30
    }
    """
    provider = config.get("provider", "openai")
    name = config.get("name", "default")
    clean_config = {k: v for k, v in config.items() if k not in ["provider", "name"]}
    return llm_manager.create_llm(name, provider, clean_config)
