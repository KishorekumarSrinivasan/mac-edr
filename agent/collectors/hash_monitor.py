"""SHA256 hashing + known-bad signature matching.

Includes the EICAR test signature (industry-standard harmless test file)
so the whole pipeline can be validated end-to-end without needing real
malware. Note from v1: compute the hash of the *actual file bytes* --
constructing a test file via shell `echo` silently mangles bytes
(backslash interpretation, trailing newline) and the hash won't match.
Use `printf '%s' ... > file` or write bytes directly in Python instead.
"""
import hashlib
import logging

logger = logging.getLogger("edr.agent.hash")

# sha256 of the standard EICAR-STANDARD-ANTIVIRUS-TEST-FILE string.
KNOWN_BAD_SIGNATURES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
}


def sha256_of_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return None


def check_file(path: str) -> dict | None:
    """Returns a hash-alert dict if `path` matches a known-bad signature."""
    digest = sha256_of_file(path)
    if digest is None:
        return None
    signature_name = KNOWN_BAD_SIGNATURES.get(digest)
    if signature_name is None:
        return None
    logger.warning("MALWARE MATCH: %s (%s) -> %s", path, digest[:12], signature_name)
    return {"path": path, "sha256": digest, "signature_name": signature_name}
