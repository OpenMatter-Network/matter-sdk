"""Every catalogue read against a live chain, read-only: no key, no submission.
Strict decoders fail when a forkless upgrade changes a layout, and this is where
that shows first. Needs the network::

    MATTER_LIVE=yes pytest tests/test_live_reads.py

``MATTER_AT_BLOCK`` pins the block; ``MATTER_LIVE_READS_OUT`` writes the results,
for ``scripts/compare-live-reads.sh`` to hold the four bindings to the same bytes.
"""

import json
import os
from pathlib import Path

import pytest

pytest.importorskip("substrateinterface")

from matter_sdk import MatterClient, canonical_json  # noqa: E402

from read_fixture import READ_FIXTURE, args_of  # noqa: E402

pytestmark = pytest.mark.skipif(
    os.environ.get("MATTER_LIVE") != "yes", reason="set MATTER_LIVE=yes to read the live chain"
)

_LIVE = json.loads(
    (Path(__file__).resolve().parents[3] / "testvectors" / "live_reads.json").read_text()
)


def _name(row) -> str:
    return f"{row['facade']}.{row['method']}"


def test_the_live_arguments_exercise_exactly_the_reads_the_catalogue_pins():
    assert {_name(row) for row in _LIVE["reads"]} == {_name(row) for row in READ_FIXTURE["reads"]}


def test_every_catalogue_read_decodes_against_the_live_runtime():
    pinned = {_name(row): row for row in READ_FIXTURE["reads"]}
    with MatterClient.connect(rpc_url=os.environ.get("MATTER_RPC_URL")) as client:
        at = os.environ.get("MATTER_AT_BLOCK") or "0x" + client.chain.finalized_head().hex()
        reads = []
        for row in _LIVE["reads"]:
            catalogued = pinned[_name(row)]
            facade = getattr(client, row["facade"])
            view = getattr(facade, READ_FIXTURE["pin_method"])(at) if catalogued["pinnable"] else facade
            result = getattr(view, row["method"])(*args_of(catalogued, row["args"]))
            # The canonical text itself: the comparison is of bytes, not parsed values.
            reads.append(
                {
                    "facade": row["facade"],
                    "method": row["method"],
                    "args": row["args"],
                    "result_json": canonical_json(result),
                }
            )

    out = os.environ.get("MATTER_LIVE_READS_OUT")
    if out:
        Path(out).write_text(json.dumps({"at": at, "reads": reads}, indent=2))
    assert len(reads) == len(_LIVE["reads"])
