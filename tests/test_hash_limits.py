"""Hash helpers obey the same resource model as every other direct operation."""

from __future__ import annotations

import base64
import hashlib
import time

import pytest

from pychef import ExecutionLimitError, ExecutionPolicy, ExecutionTimeoutError, Pipeline
from pychef.ops import digest, md5, sha1, sha256, sha512, using_policy


def test_sha256_respects_output_limit() -> None:
    with using_policy(ExecutionPolicy(max_output_bytes=8)), pytest.raises(ExecutionLimitError) as e:
        sha256(b"ABC")
    assert e.value.limit == "max_output_bytes"
    with using_policy(ExecutionPolicy(max_output_bytes=64)):
        assert len(sha256(b"ABC")) == 64


def test_sha256_respects_input_limit() -> None:
    with using_policy(ExecutionPolicy(max_input_bytes=2)), pytest.raises(ExecutionLimitError):
        sha256(b"ABC")


def test_sha256_respects_step_limit() -> None:
    with using_policy(ExecutionPolicy(max_steps=0)), pytest.raises(ExecutionLimitError):
        sha256(b"ABC")


def test_sha256_respects_deadline() -> None:
    pipeline = Pipeline().apply(lambda v: (time.sleep(0.15), v)[1]).apply(sha256)
    with pytest.raises(ExecutionTimeoutError):
        pipeline(b"A", policy=ExecutionPolicy(cooperative_deadline_seconds=0.05))


def test_sha256_nested_uses_outer_context() -> None:
    pipeline = Pipeline().apply(sha256)
    assert len(pipeline(b"A", policy=ExecutionPolicy(max_steps=2))) == 64
    with pytest.raises(ExecutionLimitError):
        pipeline(b"A", policy=ExecutionPolicy(max_steps=1))


def test_digest_raw_output_is_bytes() -> None:
    assert digest(b"abc", output="raw") == hashlib.sha256(b"abc").digest()
    assert digest(b"abc", output="bytes") == hashlib.sha256(b"abc").digest()


def test_digest_base64_output_is_text() -> None:
    expected = base64.b64encode(hashlib.sha1(b"abc").digest()).decode()
    assert digest(b"abc", algorithm="sha1", output="base64") == expected


def test_hash_helpers_keep_existing_api() -> None:
    assert md5("abc") == hashlib.md5(b"abc").hexdigest()
    with pytest.raises(ValueError, match="unsupported hash algorithm"):
        digest(b"abc", algorithm="nope")
    with pytest.raises(ValueError, match="unsupported digest output"):
        digest(b"abc", output="octal")  # type: ignore
    with pytest.raises(TypeError):
        sha256(1)  # type: ignore


@pytest.mark.parametrize("name", ["md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b"])
def test_hash_helpers_match_hashlib(name: str) -> None:
    data = bytes(range(256)) * 3
    expected = hashlib.new(name, data).hexdigest()
    helpers = {"md5": md5, "sha1": sha1, "sha256": sha256, "sha512": sha512}
    got = helpers[name](data) if name in helpers else digest(data, algorithm=name)
    assert got == expected


def test_trace_records_hash_step() -> None:
    from pychef import ExecutionContext

    context = ExecutionContext(policy=ExecutionPolicy.safe(), trace_enabled=True)
    Pipeline().apply(sha256).transform(b"A", context=context)
    assert len(context.trace) == 2  # the hash step and the enclosing stage
    assert context.steps == 2
