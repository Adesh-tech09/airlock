"""`stellar_seed` detector: plaintext Stellar seeds in tracked files. Task 6.3.

D-06: KEEP, owner-approved 2026-10-28 UTC. Offline, checksum-valid candidates only; valid test
vectors also match and remain explicitly suppressible with a reason. No funding or live-use
inference. Source comparison: `ARCHITECTURE.md` 9.4.

The candidate regex is intentionally loose and the checksum decides. A false candidate costs one
Base32 decode, and tightening the text shape instead would miss seeds written in an unexpected
context. Lines past `line_cap` reach no regex, as everywhere else, and are accounted for by
`cfg-long-line` in the engine pass.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..fingerprint import PendingFinding
from ..model import ScanContext
from ..rules import finding_for
from ..strkey import decode_seed

RULE_ID = "stellar-seed"

#: A candidate: a leading `S`, 55 more Base32 characters, and a word boundary on both sides.
#: Word-adjacent text (letters, digits or underscores) is therefore not a candidate at all.
CANDIDATE_RE = re.compile(r"\bS[A-Z2-7]{55}\b")

MESSAGE = (
    "Plaintext Stellar secret seed: the StrKey checksum validates. The encoding cannot say "
    "whether this seed is funded or live."
)


def run(ctx: ScanContext) -> Iterable[PendingFinding]:
    """Emit one HIGH finding for each checksum-valid candidate on a line at or under the cap."""
    rule = next((candidate for candidate in ctx.rules if candidate.id == RULE_ID), None)
    if rule is None:
        return ()
    findings: list[PendingFinding] = []
    for entry in ctx.entries:
        if entry.text is None:
            continue
        for number, raw_line in enumerate(entry.text.split("\n"), start=1):
            line = raw_line.removesuffix("\r")
            if len(line) > ctx.policy.line_cap:
                continue
            for match in CANDIDATE_RE.finditer(line):
                candidate = match.group()
                if decode_seed(candidate) is None:
                    continue
                findings.append(
                    finding_for(
                        rule,
                        entry,
                        number,
                        evidence=candidate,
                        message=MESSAGE,
                    )
                )
    return tuple(findings)
