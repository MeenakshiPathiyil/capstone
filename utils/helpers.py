# Utility functions used across the system

def normalize(value):
    """
    Normalize values into consistent types.

    THEORY:
    Cloud configs often store numbers/booleans as strings.
    This solves the 'representation mismatch' problem.
    """

    if isinstance(value, str):
        v = value.strip()

        # convert numeric strings → int
        if v.isdigit():
            return int(v)

        # convert boolean strings → bool
        if v.lower() in ["true", "false"]:
            return v.lower() == "true"

    return value


def flatten_dict(d, parent_key="", sep="."):
    """
    Flatten nested dictionaries into key-value pairs.

    THEORY:
    This is 'attribute projection' — converting hierarchical data
    into a flat structure so rules can match easily.
    """

    items = {}

    for k, v in d.items():
        # build hierarchical key name
        new_key = f"{parent_key}{sep}{k}" if parent_key else k

        # if nested dictionary → recurse
        if isinstance(v, dict):
            items.update(flatten_dict(v, new_key, sep))

        # if list → handle specially
        elif isinstance(v, list):
            # keep full list (needed for ANY matching later)
            items[new_key] = v

            # also flatten individual elements
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    items.update(flatten_dict(item, f"{new_key}[{i}]", sep))
                else:
                    items[f"{new_key}[{i}]"] = normalize(item)

        else:
            # store normalized scalar value
            items[new_key] = normalize(v)

    return items 