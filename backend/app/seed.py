from __future__ import annotations

from .rule_store import seed_rules
from .wiki_writer import ensure_wiki_dirs


def bootstrap() -> None:
    ensure_wiki_dirs()
    seed_rules()
