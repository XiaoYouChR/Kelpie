import json
from pathlib import Path

import pytest

from kelpie import Error, ErrorCode, Link


LINKS_FILE = Path(__file__).parents[1] / "testdata" / "links.json"


def loadCases() -> list[dict]:
    if not LINKS_FILE.exists():
        return [pytest.param(None, marks=pytest.mark.skip(reason=f"{LINKS_FILE} is missing"))]
    return json.loads(LINKS_FILE.read_text())


@pytest.mark.parametrize("case", loadCases())
def test_parse_agrees_with_shared_vectors(case: dict) -> None:
    if case["valid"]:
        assert Link.parse(case["link"]) == Link(case["name"], case["size"], case["hash"])
    else:
        with pytest.raises(Error) as raised:
            Link.parse(case["link"])
        assert raised.value.code == ErrorCode.INVALID_LINK


def test_link_text_parses_back_to_the_same_link() -> None:
    link = Link("a b|c%d 文件.iso", 9_000_000_000, "31D6CFE0D16AE931B73C59D7E0C089C0")
    assert Link.parse(str(link)) == link
