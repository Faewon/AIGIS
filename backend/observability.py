"""Structured application events; never log request bodies, tokens, or API keys."""
import json
import logging
import time

logger = logging.getLogger("aigis")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False


def event(name: str, **fields):
    logger.info(json.dumps({"event": name, "epoch_ms": int(time.time() * 1000), **fields}, default=str))
