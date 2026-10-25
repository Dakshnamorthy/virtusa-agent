import logging
from typing import Any, TypeVar

from langchain_groq import ChatGroq
from pydantic import BaseModel

from cidan.config import get_settings, require_llm_settings

logger = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)


def structured_llm(schema: type[T]) -> Any:
    settings = require_llm_settings(get_settings())
    model = ChatGroq(
        model=settings.llm_model,
        groq_api_key=settings.groq_api_key,
        timeout=settings.llm_timeout_seconds,
        max_tokens=settings.llm_max_output_tokens,
        max_retries=2,
        temperature=0,
    )
    return model.with_structured_output(schema, method="json_schema")


def invoke_structured(schema: type[T], system_prompt: str, user_prompt: str) -> T:
    runnable = structured_llm(schema)
    try:
        return runnable.invoke([("system", system_prompt), ("human", user_prompt)])
    except Exception:
        logger.exception("LLM agent invocation failed for schema %s", schema.__name__)
        raise
