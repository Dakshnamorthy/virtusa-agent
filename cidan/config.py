import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


@dataclass(frozen=True)
class Settings:
    groq_api_key: str | None
    cidan_access_token: str | None
    llm_model: str
    embedding_model: str
    chroma_persist_directory: Path
    outputs_directory: Path
    source_pdf_directory: Path
    log_level: str
    max_pdf_bytes: int = 25 * 1024 * 1024
    llm_timeout_seconds: float = 60
    llm_max_output_tokens: int = 850

    @property
    def llm_configured(self) -> bool:
        return bool(self.groq_api_key)


def get_settings() -> Settings:
    source_dir = Path(os.getenv("SOURCE_PDF_DIRECTORY", "data/source_pdfs"))
    chroma_dir = Path(os.getenv("CHROMA_PERSIST_DIRECTORY", "storage/chroma"))
    outputs_dir = Path(os.getenv("OUTPUTS_DIRECTORY", "outputs"))
    source_dir = source_dir if source_dir.is_absolute() else ROOT / source_dir
    chroma_dir = chroma_dir if chroma_dir.is_absolute() else ROOT / chroma_dir
    outputs_dir = outputs_dir if outputs_dir.is_absolute() else ROOT / outputs_dir
    return Settings(
        groq_api_key=os.getenv("GROQ_API_KEY") or None,
        cidan_access_token=os.getenv("CIDAN_ACCESS_TOKEN") or None,
        llm_model=os.getenv("LLM_MODEL", "qwen/qwen3.8-27b"),
        embedding_model=os.getenv("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5"),
        chroma_persist_directory=chroma_dir,
        outputs_directory=outputs_dir,
        source_pdf_directory=source_dir,
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
    )


class ConfigurationError(RuntimeError):
    """Raised when a requested LLM or embedding operation lacks configuration."""


def require_llm_settings(settings: Settings | None = None) -> Settings:
    active = settings or get_settings()
    if not active.llm_configured:
        raise ConfigurationError(
            "GROQ_API_KEY is not configured. Copy .env.example to .env and set "
            "the key in your local environment before running analysis."
        )
    return active
