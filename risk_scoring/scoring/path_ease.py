import math


# Authored, not empirically derived. Provisional until the complexity
# model is formally frozen. k = 0.4 -> score halves about every 1.7 hops.
_PATH_EASE_DECAY = 0.4


def compute_path_ease(path_length: int) -> float:
    """
    Compute the path-ease score for an attack path.

    A = 100 * exp(-k * (L - 1))

    Shorter paths receive higher scores because they require
    fewer traversal steps.

    Parameters
    ----------
    path_length:
        Number of edges in the attack path. Must be >= 1.

    Returns
    -------
    float
        Path-ease score in [0, 100].
    """
    if isinstance(path_length, bool) or not isinstance(path_length, int):
        raise TypeError(
            "path_length must be an int, "
            f"got {type(path_length).__name__}"
        )

    if path_length < 1:
        raise ValueError(
            f"path_length must be >= 1, got {path_length}"
        )

    return 100.0 * math.exp(
        -_PATH_EASE_DECAY * (path_length - 1)
    )