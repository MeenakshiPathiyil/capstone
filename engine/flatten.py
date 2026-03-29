def flatten_dict(d, parent_key=''):
    items = {}

    if isinstance(d, list):
        for i, v in enumerate(d):
            new_key = f"{parent_key}[{i}]"
            items.update(flatten_dict(v, new_key))
        return items

    elif isinstance(d, dict):
        for k, v in d.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            items.update(flatten_dict(v, new_key))
        return items

    else:
        return {parent_key: d}