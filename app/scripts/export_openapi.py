"""Write the API's OpenAPI document, built from the app factory.

    python -m app.scripts.export_openapi --output app/api/tests/fixtures/openapi.json

No server is started, no socket is opened and no credential is read: the
document comes from create_app() alone. This command is the only writer of the
committed snapshot, which the web app generates its TypeScript types from.
"""

import argparse
import json
import sys
from pathlib import Path


def openapi_document():
    """The OpenAPI document as text, in the committed snapshot's format."""

    from app.api.main import create_app

    return json.dumps(create_app().openapi(), indent=2, ensure_ascii=False) + "\n"


def main(argv=None):

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])

    parser.add_argument(
        "--output",
        required=True,
        help="Where to write the OpenAPI JSON."
    )

    args = parser.parse_args(argv)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(openapi_document(), encoding="utf-8")

    print("OpenAPI written to %s" % output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
