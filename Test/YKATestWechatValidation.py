from __future__ import annotations

import pytest

from YKAWechatImport import ImportDataError, validate_import_code


@pytest.mark.parametrize(
    "code",
    (
        '[["p1",0,true]]',
        '[["p1",0,1,"note"]]',
        '[["p1",0,1,"note",[1,2]]]',
        '[["p1",0,1,"",[1.0,2]]]',
        '[["p1",0,1,"",[true,2]]]',
        '[["bg1",true]]',
    ),
)
def test_validator_rejects_noncanonical_scalar_types(code: str) -> None:
    with pytest.raises(ImportDataError):
        validate_import_code(code, {"p1", "bg1"}, {"bg1"})


def test_validator_accepts_only_canonical_ordinary_and_background_rows() -> None:
    validate_import_code(
        '[["p1",23,1,"",[-6,2]],["bg1",1]]',
        {"p1", "bg1"},
        {"bg1"},
        require_all_known_keys=True,
    )
