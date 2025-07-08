# Standard library
import random
from collections import deque
from typing import Iterable, Iterator


def reservoir_of_reservoirs(
    iterable: Iterable[str], buckets: int = 50, bucket_size: int = 2000
) -> Iterator[str]:
    """Uniformly shuffle a large iterable using minimal memory.

    This implements a memory-efficient, multi-reservoir version of reservoir sampling,
    useful for shuffling large streams of IPs before enqueuing.

    Args:
        iterable (Iterable[str]): Iterable of IP address strings.
        buckets (int, optional): Number of reservoir buckets. Default is 50.
        bucket_size (int, optional): Size of each reservoir bucket. Default is 2000.

    Yields:
        str: A uniformly shuffled IP address string.

    Notes:
        - Minimizes memory usage by limiting the number of stored IPs at any time.
        - Provides good-enough randomization for scanning or queueing purposes.
    """
    reservoirs = [deque() for _ in range(buckets)]

    for item in iterable:
        for reservoir in reservoirs:
            if len(reservoir) < bucket_size:
                reservoir.append(item)
                break
        else:
            q = random.randrange(buckets)
            j = random.randrange(bucket_size)

            evicted = reservoirs[q][j]
            reservoirs[q][j] = item
            yield evicted

    for reservoir in reservoirs:
        tmp = list(reservoir)
        random.shuffle(tmp)
        yield from tmp
