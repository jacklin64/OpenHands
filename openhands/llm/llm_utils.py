import copy
from typing import TYPE_CHECKING, Any

from openhands.core.config import LLMConfig
from openhands.core.logger import openhands_logger as logger

if TYPE_CHECKING:
    from litellm import ChatCompletionToolParam


def get_assistant_message_text(
    assistant_msg: Any,
    *,
    append_thinking_content: bool = False,
) -> str:
    """Return visible assistant text, optionally prefixed with reasoning/thinking fields.

    Hosted reasoning APIs (e.g. NVIDIA + LiteLLM) often put chain-of-thought in
    ``thinking_content`` / ``reasoning_content`` while ``content`` holds the answer only.
    """
    content = getattr(assistant_msg, 'content', None)
    if isinstance(content, list):
        text_parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get('type') == 'text':
                text_parts.append(str(item.get('text', '')))
            elif hasattr(item, 'text'):
                text_parts.append(str(item.text))
        text = '\n'.join(p for p in text_parts if p)
    elif content is None:
        text = ''
    else:
        text = str(content)

    if not append_thinking_content:
        return text

    thinking_parts: list[str] = []
    for attr in ('thinking_content', 'reasoning_content'):
        val = getattr(assistant_msg, attr, None)
        if isinstance(val, str) and val.strip():
            thinking_parts.append(val.strip())

    provider_fields = getattr(assistant_msg, 'provider_specific_fields', None)
    if isinstance(provider_fields, dict):
        for key in ('thinking_content', 'reasoning_content'):
            val = provider_fields.get(key)
            if isinstance(val, str) and val.strip():
                thinking_parts.append(val.strip())

    thinking = '\n\n'.join(thinking_parts).strip()
    if not thinking:
        return text
    text = text.strip()
    if text:
        return f'{thinking}</think>{text}'
    return thinking


def check_tools(
    tools: list['ChatCompletionToolParam'], llm_config: LLMConfig
) -> list['ChatCompletionToolParam']:
    """Checks and modifies tools for compatibility with the current LLM."""
    # Special handling for Gemini models which don't support default fields and have limited format support
    if 'gemini' in llm_config.model.lower():
        logger.info(
            f'Removing default fields and unsupported formats from tools for Gemini model {llm_config.model} '
            "since Gemini models have limited format support (only 'enum' and 'date-time' for STRING types)."
        )
        # prevent mutation of input tools
        checked_tools = copy.deepcopy(tools)
        # Strip off default fields and unsupported formats that cause errors with gemini-preview
        for tool in checked_tools:
            if 'function' in tool and 'parameters' in tool['function']:
                if 'properties' in tool['function']['parameters']:
                    for prop_name, prop in tool['function']['parameters'][
                        'properties'
                    ].items():
                        # Remove default fields
                        if 'default' in prop:
                            del prop['default']

                        # Remove format fields for STRING type parameters if the format is unsupported
                        # Gemini only supports 'enum' and 'date-time' formats for STRING type
                        if prop.get('type') == 'string' and 'format' in prop:
                            supported_formats = ['enum', 'date-time']
                            if prop['format'] not in supported_formats:
                                logger.info(
                                    f'Removing unsupported format "{prop["format"]}" for STRING parameter "{prop_name}"'
                                )
                                del prop['format']
        return checked_tools
    return tools
