"""`python -m arer` - the same CLI as the `arer` console script.

The Phase 6.5 watcher (src/arer/watcher.py) launches every mail's scan this
way: a fresh interpreter per mail keeps a crash or hang isolated from the
watcher itself.
"""
from .cli import main

if __name__ == "__main__":
    main()
