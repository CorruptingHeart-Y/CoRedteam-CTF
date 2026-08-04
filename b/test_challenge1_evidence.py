import json
from pathlib import Path


EVIDENCE_PATH = Path(__file__).parent / "evidence" / "challenge1_success.json"


def test_challenge1_evidence_file_exists():
    assert EVIDENCE_PATH.is_file()


def test_challenge1_exploit_chain_order():
    evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))

    assert evidence["exploit_chain"] == [
        "ssti_reflection",
        "command_execution",
        "arbitrary_file_read",
    ]


def test_challenge1_validator_passed():
    evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))

    assert evidence["validator"]["passed"] is True
