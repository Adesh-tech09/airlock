"""`strkey` decoding and the `stellar_seed` detector (tasks 6.2 and 6.3).

Every candidate here is built at test time from bytes by `encode_seed`, so no complete
live-looking seed is committed (`AGENTS.md` 4). The controls cover each way a 56-character `S...`
string can fail: encoding, length, version and checksum.
"""

from __future__ import annotations

from dataclasses import replace

from tests.fixtures import Case, File, context
from tests.fixtures.stellar_seed import CASE_PATH, SEED_BODY, encode_seed

from airlock.model import Severity
from airlock.runner import scan
from airlock.strkey import crc16_xmodem, decode_seed

RULE_ID = "stellar-seed"


def findings_for(text: str, *, line_cap: int = 200) -> list:
    ctx = context(Case(files=(File(CASE_PATH, text=text),)))
    if line_cap != ctx.policy.line_cap:
        ctx = replace(ctx, policy=replace(ctx.policy, line_cap=line_cap))
    return [finding for finding in scan(ctx) if finding.rule_id == RULE_ID]


class TestDecodeSeed:
    def test_a_vector_built_from_the_byte_contract_returns_the_seed(self) -> None:
        candidate = encode_seed()
        assert len(candidate) == 56
        assert decode_seed(candidate) == SEED_BODY

    def test_the_crc_helper_matches_its_published_check_value(self) -> None:
        # CRC16-XMODEM's standard check value for the ASCII digits "123456789".
        assert crc16_xmodem(b"123456789") == 0x31C3

    def test_a_lowercase_candidate_is_not_canonical(self) -> None:
        assert decode_seed(encode_seed().lower()) is None

    def test_a_wrong_version_byte_is_rejected_even_with_a_valid_checksum(self) -> None:
        assert decode_seed(encode_seed(version=0x91)) is None

    def test_a_checksum_that_does_not_match_the_body_is_rejected(self) -> None:
        correct = crc16_xmodem(bytes([0x90]) + SEED_BODY)
        assert decode_seed(encode_seed(checksum=(correct + 1) & 0xFFFF)) is None

    def test_a_55_character_candidate_is_rejected(self) -> None:
        assert decode_seed(encode_seed()[:-1]) is None

    def test_a_57_character_candidate_is_rejected(self) -> None:
        assert decode_seed(encode_seed() + "A") is None

    def test_a_non_base32_character_is_rejected(self) -> None:
        candidate = encode_seed()
        # `0` and `1` are outside the RFC4648 Base32 alphabet.
        assert decode_seed(candidate[:-1] + "0") is None


class TestDetector:
    def test_a_valid_seed_is_one_high_finding_on_its_line(self) -> None:
        text = "PORT=3000\nSTELLAR_SECRET=" + encode_seed() + "\n"
        findings = findings_for(text)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == RULE_ID
        assert finding.severity is Severity.HIGH
        assert finding.line == 2
        assert finding.path == CASE_PATH

    def test_the_finding_is_suppressible_with_a_reason(self) -> None:
        assert findings_for("STELLAR_SECRET=" + encode_seed() + "\n")[0].suppressible is True

    def test_the_message_claims_no_funding_or_live_use(self) -> None:
        message = findings_for(encode_seed() + "\n")[0].message
        assert "checksum" in message
        assert "funded" in message and "live" in message

    def test_both_candidates_on_one_line_are_reported(self) -> None:
        vector = encode_seed()
        assert len(findings_for(f"{vector} {vector}\n")) == 2

    def test_a_checksum_invalid_candidate_does_not_fire(self) -> None:
        correct = crc16_xmodem(bytes([0x90]) + SEED_BODY)
        text = "STELLAR_SECRET=" + encode_seed(checksum=(correct + 1) & 0xFFFF) + "\n"
        assert findings_for(text) == []

    def test_a_wrong_version_candidate_does_not_fire(self) -> None:
        assert findings_for("STELLAR_SECRET=" + encode_seed(version=0x91) + "\n") == []

    def test_a_lowercase_candidate_does_not_fire(self) -> None:
        assert findings_for("STELLAR_SECRET=" + encode_seed().lower() + "\n") == []

    def test_a_55_character_candidate_does_not_fire(self) -> None:
        assert findings_for("STELLAR_SECRET=" + encode_seed()[:-1] + "\n") == []

    def test_a_57_character_candidate_does_not_fire(self) -> None:
        assert findings_for("STELLAR_SECRET=" + encode_seed() + "A\n") == []

    def test_letters_touching_the_candidate_hide_it_from_the_regex(self) -> None:
        # The documented limit of the candidate regex, not a checksum failure: retrying the
        # decode cannot recover a string the pattern never found (ARCHITECTURE.md 9.4).
        vector = encode_seed()
        assert findings_for("X" + vector + "\n") == []
        assert findings_for("_" + vector + "\n") == []

    def test_a_candidate_past_the_line_cap_is_left_to_the_cap_rule(self) -> None:
        text = "STELLAR_SECRET=" + encode_seed() + "\n"
        assert findings_for(text, line_cap=40) == []


class TestFixtureBuilder:
    def test_the_builder_builds_a_seed_at_call_time(self) -> None:
        from tests.fixtures.stellar_seed import stellar_seed

        fixture = stellar_seed()
        assert fixture.positive is not None and fixture.negative is not None
        positive = fixture.positive.files[0].text or ""
        negative = fixture.negative.files[0].text or ""
        assert encode_seed() in positive
        assert encode_seed() not in negative
