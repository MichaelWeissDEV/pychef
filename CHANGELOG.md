# Changelog

All notable changes to this project are documented here. Releases follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Aligned Charcode, HTML Entity, Base85, Float, Punycode, and general radix
  conversion arguments and outputs with the pinned CyberChef implementation.
- Reworked Template JSON rendering, fuzzy matching, frequency distribution,
  chart parsing, smart-character escaping, string escaping, random-generator
  formats, and offset highlighting.
- Added validation limits for De Bruijn and Lorem Ipsum generators and hardened
  chart and template output escaping.

### Documentation

- Added the Read the Docs URL to package metadata and the project README so the
  next distribution published to PyPI links directly to the hosted manual.

## [0.1.0] - 2026-08-01

### Added

- The `cyberchef-py` distribution with the `pychef` import package.
- Pure-Python implementations for all 502 CyberChef operation names.
- CyberChef-compatible recipes with flow-control support.
- Immutable transformation pipelines with composition, branching, tracing,
  and output concatenation.
- CTF helpers for packing, endianness, XOR, hashing, AES modes, hexdumps, and
  de Bruijn patterns.
- Structured Ethernet, IP, TCP, UDP, DNS, PCAP, and PCAPNG parsing.
- Type information, pytest coverage, Ruff linting, and ty type checking.

[Unreleased]: https://github.com/MichaelWeissDEV/pychef/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MichaelWeissDEV/pychef/releases/tag/v0.1.0
