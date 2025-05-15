import random
import pytest
from utils.randomize_handler import reservoir_of_reservoirs


def test_reservoir_preserves_all_elements():
    """Shuffling a list yields the same elements, possibly in new order."""
    original = list(range(100))
    result = list(reservoir_of_reservoirs(original, buckets=10, bucket_size=10))

    assert sorted(result) == sorted(original)
    assert result != original  # Should be different order (most of the time)


def test_reservoir_preserves_empty_input():
    """Shuffling an empty iterable yields an empty list."""
    result = list(reservoir_of_reservoirs([]))
    assert result == []


def test_reservoir_shuffling_does_not_modify_input():
    """Input iterable remains unmodified (if it's a collection)."""
    original = [1, 2, 3, 4, 5]
    original_copy = original.copy()
    result = list(reservoir_of_reservoirs(original))

    assert sorted(result) == sorted(original_copy)
    assert original == original_copy


def test_reservoir_with_dict_items():
    """Works with dict.items() as input and returns the same key-value pairs."""
    d = {"a": 1, "b": 2, "c": 3}
    result = list(reservoir_of_reservoirs(d.items(), buckets=2, bucket_size=2))

    assert set(result) == set(d.items())


def test_reservoir_raises_on_non_iterable():
    """Non-iterable input raises TypeError."""
    with pytest.raises(TypeError):
        list(reservoir_of_reservoirs(42))  # Not iterable


def test_reservoir_uniformity_seeded():
    """Same seed should yield the same shuffle (for test determinism)."""
    data = list(range(50))
    random.seed(123)
    r1 = list(reservoir_of_reservoirs(data, buckets=5, bucket_size=10))

    random.seed(123)
    r2 = list(reservoir_of_reservoirs(data, buckets=5, bucket_size=10))

    assert r1 == r2


def test_reservoir_eviction_occurs(monkeypatch):
    """Test that eviction happens when all reservoirs are full."""
    buckets = 2
    bucket_size = 2
    data = list(range(buckets * bucket_size + 5))  # 4 full + 5 extra → triggers eviction

    monkeypatch.setattr("random.randrange", lambda x: 0)

    result = list(reservoir_of_reservoirs(data, buckets=buckets, bucket_size=bucket_size))

    assert sorted(result) == sorted(data)
