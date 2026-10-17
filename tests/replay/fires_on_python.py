"""fires_on rules that cannot be written as declarative conditions (tests/replay/fires_on.py), one function per D-ID, each
with the reason it stays in Python. None today: every replayed detection's rule is in tests/replay/fires_on/<D-ID>.yaml."""

RULES = {}   # {D-ID: {"fires": function(event) -> bool, "reason": "why it cannot be declarative"}}
