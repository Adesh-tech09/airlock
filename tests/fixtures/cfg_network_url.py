"""`cfg-network` URL context fixtures (#54).

A URL is a network capability only when something can fetch it: a call argument, or the value of
a key that names a URL, endpoint, host or request. A documentation URL in a comment, or in a
string the config never fetches, is prose. Trigger text is assembled at call time (`AGENTS.md` 4).
"""

from __future__ import annotations

from . import Case, File, assemble

CASE_PATH = "postcss.config.js"
DOCS_URL = assemble("https://post", "css.org/docs")
FETCH = assemble("fet", "ch")
MANIFEST_URL = assemble("https://example.invalid", "/manifest")
PROXY_URL = assemble("https://example.invalid", "/proxy")


def _config(*lines: str) -> Case:
    return Case(files=(File(CASE_PATH, text="\n".join(lines) + "\n"),))


def docs_comment() -> Case:
    return _config(
        "// Plugin options: " + DOCS_URL,
        "export default {",
        "  plugins: [],",
        "};",
    )


def unfetched_string() -> Case:
    return _config(
        "export default {",
        f'  banner: "{DOCS_URL}",',
        "};",
    )


def call_argument() -> Case:
    return _config(
        "export default {",
        f"  manifest: {FETCH}({MANIFEST_URL!r}),",
        "};",
    )


def network_named_value() -> Case:
    return _config(
        "export default {",
        f'  proxyUrl: "{PROXY_URL}",',
        "};",
    )
