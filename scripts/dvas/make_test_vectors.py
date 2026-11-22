"""Write the pinned canonical-encoding test vectors (tests/dvas/vectors/canonical_v1.json).

Run once when the encoding version changes. The test suite then requires the
current implementation to reproduce these bytes, leaf hashes and root exactly.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "dvas"))

from test_canonical import VECTORS, _vector_payload  # noqa: E402

VECTORS.parent.mkdir(parents=True, exist_ok=True)
VECTORS.write_text(json.dumps(_vector_payload(), indent=2, sort_keys=True) + "\n")
print("wrote", VECTORS)
