"""Attack taxonomy and the channel each class uses.

The *channel* matters for the spotlighting defense: prompt-layer spotlighting delimits
untrusted **data** (tool outputs) as "not instructions", but tool **metadata**
(descriptions) is presented as part of the tool schema and is not delimited. So a
description-poisoning attack survives spotlighting while output-borne attacks do not —
this is exactly why spotlighting is only partially effective.
"""

from __future__ import annotations

from typing import Literal

from ..eval.schemas import AttackType

Channel = Literal["metadata", "data"]

#: Attacks delivered via tool description / metadata (not delimited by spotlighting).
METADATA_CHANNEL_ATTACKS: frozenset[AttackType] = frozenset(
    {AttackType.tool_description_poisoning, AttackType.metadata_poisoning}
)

#: Attacks delivered via tool output / retrieved data (delimited by spotlighting).
DATA_CHANNEL_ATTACKS: frozenset[AttackType] = frozenset(
    {
        AttackType.tool_output_poisoning,
        AttackType.argument_substitution,
        AttackType.amount_substitution,
        AttackType.cross_tool_contamination,
        AttackType.retrieval_injection,
    }
)


def channel_for(attack_type: AttackType) -> Channel:
    if attack_type in METADATA_CHANNEL_ATTACKS:
        return "metadata"
    return "data"
