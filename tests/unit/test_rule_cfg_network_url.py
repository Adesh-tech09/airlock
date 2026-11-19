"""`cfg-network` requires a URL to sit in a network context (#54).

Before this rule was narrowed, any `https://` literal was a WARN, so a documentation URL in a
comment reported a capability the file did not have. The shipped positive and negative pair still
passes; the cases here pin the call-argument branch and the network-named-value branch that
replaced the bare literal.
"""

from __future__ import annotations

from tests.fixtures import Case, fired
from tests.fixtures.cfg_network_url import (
    call_argument,
    docs_comment,
    network_named_value,
    unfetched_string,
)
from tests.fixtures.config_role import cfg_network

RULE_ID = "cfg-network"


def fires(case: Case) -> bool:
    return RULE_ID in fired(case)


class TestUrlContext:
    def test_a_documentation_url_in_a_comment_stays_quiet(self) -> None:
        assert not fires(docs_comment())

    def test_a_url_in_a_string_the_config_never_fetches_stays_quiet(self) -> None:
        assert not fires(unfetched_string())

    def test_a_url_passed_to_a_call_still_fires(self) -> None:
        assert fires(call_argument())

    def test_a_url_as_a_network_named_value_still_fires(self) -> None:
        assert fires(network_named_value())


class TestShippedPair:
    def test_the_shipped_positive_still_fires(self) -> None:
        fixture = cfg_network()
        assert fixture.positive is not None
        assert fires(fixture.positive)

    def test_the_shipped_negative_stays_quiet(self) -> None:
        fixture = cfg_network()
        assert fixture.negative is not None
        assert not fires(fixture.negative)
