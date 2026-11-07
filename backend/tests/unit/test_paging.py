import pytest

from app.errors import InvalidFilterError
from app.services.paging import MAX_LIMIT, MAX_OFFSET, check_paging


def test_limits_and_offsets_inside_the_range_are_accepted():
    check_paging(1, 0)
    check_paging(MAX_LIMIT, 0)
    check_paging(50, MAX_OFFSET)


def test_the_biggest_offset_is_the_biggest_signed_64_bit_integer():
    assert MAX_OFFSET == 2**63 - 1       # larger values overflow the database's bigint


@pytest.mark.parametrize("limit,offset", [
    (0, 0), (MAX_LIMIT + 1, 0), (-1, 0), (50, -1), (50, MAX_OFFSET + 1), (50, 10**30),
])
def test_values_outside_the_range_are_an_invalid_filter(limit, offset):
    with pytest.raises(InvalidFilterError):
        check_paging(limit, offset)
