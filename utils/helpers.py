import json
from pathlib import Path

# Utility functions used across the system

def normalize(value):
    """Normalize values into consistent types."""

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
    """Flatten nested dictionaries into key-value pairs."""

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


def write_json(payload, output_path):
    r"""Write one JSON file, creating its directory. Returns the path.

    Trailing newline, so the file is a well-formed text file and a golden-file
    diff does not report "\ No newline at end of file".
    """

    output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as handle:

        json.dump(payload, handle, indent=2)

        handle.write("\n")

    return output_path
