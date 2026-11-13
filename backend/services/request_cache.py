"""Tiny in-memory map of request_id -> what was scanned, so that a later
"Report as fraud" tap can be linked back to the right VPA."""
from collections import OrderedDict

_MAX = 500
_cache: "OrderedDict[str, dict]" = OrderedDict()


def remember(request_id: str, **data) -> None:
    _cache[request_id] = data
    while len(_cache) > _MAX:
        _cache.popitem(last=False)


def recall(request_id: str) -> dict:
    return _cache.get(request_id, {})
