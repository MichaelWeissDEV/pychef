"""Compatibility and structure tests for the public API surface."""

from __future__ import annotations

import importlib
import json
import subprocess
import sys

import pytest

import pychef
from pychef import Recipe, RecipeError

# ``pychef.__all__`` as of release-candidate base commit 9d39063: must stay importable.
BASELINE_ALL = (
    "BakeResult",
    "Chef",
    "CompatibilityReport",
    "Data",
    "ExecutionContext",
    "ExecutionLimitError",
    "ExecutionPolicy",
    "ExecutionTimeoutError",
    "InvalidOperationArgumentsError",
    "IsolatedWorker",
    "NetworkPolicy",
    "Operation",
    "OperationArgSpec",
    "OperationError",
    "OperationPermissionError",
    "OperationRegistry",
    "OperationSpec",
    "Pipeline",
    "PipelineTrace",
    "PolicyDecision",
    "PyChefError",
    "Recipe",
    "RecipeConfig",
    "RecipeError",
    "RecipeStep",
    "TraceStep",
    "UnknownOperationError",
    "aes_decrypt",
    "aes_encrypt",
    "aes_gcm_decrypt",
    "aes_gcm_encrypt",
    "bake",
    "bake_isolated",
    "chunks",
    "compatibility_report",
    "cyclic",
    "cyclic_find",
    "decode_bytes",
    "digest",
    "digests",
    "encode_bytes",
    "flat",
    "get_operation_spec",
    "hexdump",
    "json_safe",
    "list_operation_specs",
    "list_operations",
    "md5",
    "normalize_host",
    "p16",
    "p16be",
    "p16le",
    "p32",
    "p32be",
    "p32le",
    "p64",
    "p64be",
    "p64le",
    "p8",
    "pack",
    "packet_json",
    "parse_arp_packet",
    "parse_capture",
    "parse_dns_message",
    "parse_ethernet_frame",
    "parse_icmp_message",
    "parse_ipv4_packet",
    "parse_ipv6_packet",
    "parse_packet",
    "parse_pcap",
    "parse_pcapng",
    "parse_tcp_segment",
    "parse_udp_datagram",
    "read_capture",
    "registry",
    "rol",
    "ror",
    "sha1",
    "sha256",
    "sha512",
    "swap_endian",
    "u16",
    "u16be",
    "u16le",
    "u32",
    "u32be",
    "u32le",
    "u64",
    "u64be",
    "u64le",
    "u8",
    "unpack",
    "xor_bytes",
)


def test_baseline_symbols_are_still_exported_and_resolve() -> None:
    assert not set(BASELINE_ALL) - set(pychef.__all__)
    assert not [name for name in BASELINE_ALL if getattr(pychef, name, None) is None]


def test_all_entries_resolve_and_are_unique() -> None:
    assert len(set(pychef.__all__)) == len(pychef.__all__)
    for name in pychef.__all__:
        assert hasattr(pychef, name), name


def test_version_matches_installed_distribution() -> None:
    from importlib.metadata import version

    assert pychef.__version__ == version("cyberchef-py")


def test_version_falls_back_without_distribution_metadata() -> None:
    from pathlib import Path

    src = Path(pychef.__file__).resolve().parents[1]
    code = (
        f"import sys; sys.path.insert(0, {str(src)!r});"
        "from importlib.metadata import PackageNotFoundError, version;"
        "import pychef;"
        "print(pychef.__version__)"
    )
    # ``-S`` drops site-packages (including any dist-info of the editable install).
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", code], capture_output=True, text=True, check=False
    )
    assert result.stdout.strip() == "0+unknown", result.stderr


def test_dir_lists_lazy_submodules() -> None:
    assert {"ops", "operations"} <= set(dir(pychef))


def test_import_pychef_is_lazy() -> None:
    code = (
        "import sys, pychef;"
        "loaded = [m for m in sys.modules if m.startswith('pychef.operations.')];"
        "assert not loaded, loaded;"
        "assert 'pychef.operations.aes' not in sys.modules;"
        "assert 'pychef.ops' not in sys.modules"
    )
    subprocess.run([sys.executable, "-I", "-c", code], check=True)


def test_ops_is_importable_from_top_level_attribute() -> None:
    assert importlib.import_module("pychef.ops") is pychef.ops


# --- Recipe serialization -------------------------------------------------------


def test_recipe_config_round_trip_and_repr() -> None:
    recipe = Recipe(["From Hex", {"op": "To Base64", "args": ["A-Za-z0-9+/="], "disabled": True}])
    assert len(recipe) == 2
    assert repr(recipe) == "Recipe(['From Hex', 'To Base64'])"
    config = recipe.to_config()
    assert config == [
        {"op": "From Hex", "args": []},
        {"op": "To Base64", "args": ["A-Za-z0-9+/="], "disabled": True},
    ]
    assert Recipe(config).steps == recipe.steps
    assert Recipe.from_json(recipe.to_json(indent=2)).steps == recipe.steps
    assert json.loads(recipe.to_json()) == config
    assert Recipe.from_json(b'["From Hex"]').steps[0].op == "From Hex"


def test_recipe_json_errors_are_explicit() -> None:
    with pytest.raises(RecipeError, match="valid JSON"):
        Recipe.from_json("{nope")
    with pytest.raises(RecipeError, match="list of steps"):
        Recipe.from_json('{"op": "From Hex"}')
    with pytest.raises(TypeError):
        Recipe([{"op": "XOR", "args": [b"\x01"]}]).to_json()
