from utils.helpers import flatten_dict

def extract_attributes(resource):
    """
    Convert raw_properties into rule-friendly format.

    THEORY:
    Implements 'dual representation':
    - flat fields → simple rule matching
    - structured data → complex/nested matching
    """

    raw = resource.get("raw_properties", {})
    flat = flatten_dict(raw)

    return {
        **resource,          # original resource
        **flat,              # flattened attributes
        "_structured": raw   # keep original structure for advanced logic
    }


def process_resources(resources):
    """
    Apply extraction to all resources.

    THEORY:
    This is the transformation stage in the pipeline.
    """
    return [extract_attributes(r) for r in resources]