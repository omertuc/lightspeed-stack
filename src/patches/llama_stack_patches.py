"""Monkey patches for llama-stack dependency."""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from llama_stack.providers.inline.agents.meta_reference.persistence import (
        LlamaStackSessionMemoryPersistence,
    )

logger = logging.getLogger(__name__)


def patch_session_turns_sorting() -> None:
    """
    Monkey patch to fix session turns ordering in llama-stack.
    
    This patch applies the fix from:
    https://github.com/meta-llama/llama-stack/commit/5e18d4d097d683056174b3c8b270806326e7ee96
    
    The fix ensures that session turns are sorted by started_at timestamp
    to maintain consistent ordering when retrieved from the kvstore.
    """
    try:
        from llama_stack.providers.inline.agents.meta_reference.persistence import (
            LlamaStackSessionMemoryPersistence,
        )
        
        # Store the original method
        original_get_session_turns = LlamaStackSessionMemoryPersistence.get_session_turns
        
        async def patched_get_session_turns(self, session_id: str):
            """Patched version of get_session_turns that sorts turns by started_at."""
            # Call the original method to get the turns
            turns = await original_get_session_turns(self, session_id)
            
            # The kvstore does not guarantee order, so we sort by started_at
            # to ensure consistent ordering of turns.
            turns.sort(key=lambda t: t.started_at)
            
            return turns
        
        # Apply the monkey patch
        LlamaStackSessionMemoryPersistence.get_session_turns = patched_get_session_turns
        
        logger.info("Successfully applied llama-stack session turns sorting patch")
        
    except ImportError as e:
        logger.warning(f"Could not apply llama-stack patch - module not available: {e}")
    except Exception as e:
        logger.error(f"Failed to apply llama-stack patch: {e}")


def apply_all_patches() -> None:
    """Apply all llama-stack monkey patches."""
    patch_session_turns_sorting()