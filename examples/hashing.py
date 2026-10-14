"""Hash text and bytes consistently."""

import hashlib

from pychef import digests
from pychef.ops import digest, md5, sha1, sha256


def main() -> None:
    message = b"PyChef"
    # One format everywhere: lowercase hexadecimal text.
    assert sha256(message) == hashlib.sha256(message).hexdigest()
    assert md5("PyChef") == md5(message)  # str is UTF-8 encoded
    assert sha1(message) == hashlib.sha1(message).hexdigest()

    # Other encodings and algorithms through `digest`.
    raw = digest(message, algorithm="sha256", output="raw")
    assert isinstance(raw, bytes) and raw.hex() == sha256(message)
    assert digest(message, algorithm="sha3-256")  # any hashlib algorithm

    # Several algorithms at once.
    summary = digests(message, ("md5", "sha256"))
    assert set(summary) == {"md5", "sha256"}
    for algorithm, value in summary.items():
        print(f"{algorithm}: {value}")


if __name__ == "__main__":
    main()
