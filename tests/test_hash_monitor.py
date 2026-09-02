"""Guards against the exact v1 bug: constructing a test file via shell
`echo` silently mangles bytes, so its hash won't match the known signature."""
import hashlib
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

EICAR_STRING = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def test_eicar_bytes_hash_matches_known_signature():
    from collectors.hash_monitor import KNOWN_BAD_SIGNATURES, sha256_of_file

    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(EICAR_STRING.encode("ascii"))
        path = f.name

    try:
        digest = sha256_of_file(path)
        assert digest in KNOWN_BAD_SIGNATURES, (
            "EICAR file bytes did not match the known signature -- "
            "check for byte mangling (trailing newline, escape interpretation)"
        )
    finally:
        os.remove(path)


def test_hash_mismatch_on_trailing_newline():
    """Demonstrates why signature-based detection is brittle: one extra
    byte defeats an exact-hash match entirely."""
    from collectors.hash_monitor import sha256_of_file

    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write((EICAR_STRING + "\n").encode("ascii"))
        path = f.name

    try:
        digest = sha256_of_file(path)
        exact_digest = hashlib.sha256(EICAR_STRING.encode("ascii")).hexdigest()
        assert digest != exact_digest
    finally:
        os.remove(path)


def test_nonexistent_file_returns_none():
    from collectors.hash_monitor import sha256_of_file
    assert sha256_of_file("/nonexistent/path/should/not/exist") is None
