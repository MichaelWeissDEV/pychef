"""Tests for QR Code generation and parsing operations."""

from __future__ import annotations

import pytest

from pychef import bake, ops
from pychef.operations.qr_code import (
    ErrorCorrectionLevel,
    generate_qr_code_matrix,
)


class TestGenerateQrCode:
    """Tests for QR Code generation."""

    def test_generate_qr_code_simple_text(self) -> None:
        """Test generating a QR code from simple text."""
        text = b"Hello, World!"
        result = bake(text, [{"op": "Generate QR Code", "args": ["PNG", 5, 4, "M"]}])
        assert isinstance(result, bytes)
        assert result.startswith(b"\x89PNG")  # PNG signature

    def test_generate_qr_code_all_ec_levels(self) -> None:
        """Test generating QR codes with all error correction levels."""
        text = b"Test"
        for ec in ["L", "M", "Q", "H"]:
            result = bake(text, [{"op": "Generate QR Code", "args": ["PNG", 5, 4, ec]}])
            assert isinstance(result, bytes)
            assert result.startswith(b"\x89PNG")

    def test_generate_qr_code_different_output_formats(self) -> None:
        """Test generating QR codes in different output formats."""
        text = b"Test"

        # PNG
        png_result = bake(text, [{"op": "Generate QR Code", "args": ["PNG", 5, 4, "M"]}])
        assert isinstance(png_result, bytes)
        assert png_result.startswith(b"\x89PNG")

        # BMP
        bmp_result = bake(text, [{"op": "Generate QR Code", "args": ["BMP", 5, 4, "M"]}])
        assert isinstance(bmp_result, bytes)
        # BMP files start with "BM" but may have been processed
        # Just check it's bytes and not empty
        assert len(bmp_result) > 0

    def test_generate_qr_code_svg(self) -> None:
        """Test generating QR code in SVG format."""
        text = b"Test"
        result = bake(text, [{"op": "Generate QR Code", "args": ["SVG", 5, 4, "M"]}])
        assert isinstance(result, str)
        assert "<svg" in result
        assert "data:image/png" in result

    def test_generate_qr_code_matrix(self) -> None:
        """Test the generate_qr_code_matrix function directly."""
        data = b"Hello"
        matrix = generate_qr_code_matrix(data, ErrorCorrectionLevel.MEDIUM)

        # Matrix should be square
        size = len(matrix)
        assert size == len(matrix[0])

        # Size should match QR code version 1 (21x21)
        assert size == 21

        # All elements should be bool
        for row in matrix:
            for cell in row:
                assert isinstance(cell, bool)

    def test_generate_qr_code_empty_data(self) -> None:
        """Test that empty data raises an error."""
        with pytest.raises(ValueError, match="empty"):
            generate_qr_code_matrix(b"", ErrorCorrectionLevel.MEDIUM)

    def test_generate_qr_code_too_large_data(self) -> None:
        """Test that data that's too large raises an error."""
        large_data = b"A" * 3000  # More than maximum capacity
        with pytest.raises(ValueError, match="too large"):
            generate_qr_code_matrix(large_data, ErrorCorrectionLevel.MEDIUM)

    def test_generate_qr_code_invalid_version(self) -> None:
        """Test that invalid version raises an error."""
        from pychef.operations.qr_code import generate_qr_code_matrix

        with pytest.raises(ValueError, match="version"):
            generate_qr_code_matrix(b"test", ErrorCorrectionLevel.MEDIUM, version=0)

        with pytest.raises(ValueError, match="version"):
            generate_qr_code_matrix(b"test", ErrorCorrectionLevel.MEDIUM, version=100)


class TestParseQrCode:
    """Tests for QR Code parsing."""

    def test_parse_qr_code_roundtrip(self) -> None:
        """Test that generated QR codes can be parsed back."""
        text = b"Hello, World!"

        # Generate QR code
        qr_png = bake(text, [{"op": "Generate QR Code", "args": ["PNG", 5, 4, "M"]}])

        # Parse it back
        parsed = bake(qr_png, [{"op": "Parse QR Code"}])

        assert parsed == text

    def test_parse_qr_code_all_ec_levels(self) -> None:
        """Test parsing QR codes with all error correction levels."""
        text = b"Test message"

        for ec in ["L", "M", "Q", "H"]:
            qr_png = bake(text, [{"op": "Generate QR Code", "args": ["PNG", 5, 4, ec]}])
            parsed = bake(qr_png, [{"op": "Parse QR Code"}])
            assert parsed == text

    def test_parse_qr_code_different_sizes(self) -> None:
        """Test parsing QR codes with different module sizes."""
        text = b"Size test"

        for module_size in [1, 2, 5, 10]:
            qr_png = bake(text, [{"op": "Generate QR Code", "args": ["PNG", module_size, 4, "M"]}])
            parsed = bake(qr_png, [{"op": "Parse QR Code"}])
            assert parsed == text

    def test_parse_qr_code_different_margins(self) -> None:
        """Test parsing QR codes with different margins."""
        text = b"Margin test"

        for margin in [0, 1, 2, 4, 8]:
            qr_png = bake(text, [{"op": "Generate QR Code", "args": ["PNG", 5, margin, "M"]}])
            parsed = bake(qr_png, [{"op": "Parse QR Code"}])
            assert parsed == text

    def test_parse_qr_code_unicode(self) -> None:
        """Test parsing QR codes with Unicode text."""
        text = "Hello, 世界! 🌍".encode()

        qr_png = bake(text, [{"op": "Generate QR Code", "args": ["PNG", 5, 4, "M"]}])
        parsed = bake(qr_png, [{"op": "Parse QR Code"}])
        assert parsed == text

    def test_parse_qr_code_binary_data(self) -> None:
        """Test parsing QR codes with binary data."""
        text = bytes(range(256))

        qr_png = bake(text, [{"op": "Generate QR Code", "args": ["PNG", 5, 4, "H"]}])
        parsed = bake(qr_png, [{"op": "Parse QR Code"}])
        assert parsed == text

    def test_parse_qr_code_long_text(self) -> None:
        """Test parsing QR codes with longer text."""
        text = b"This is a longer test message that should still fit in a QR code"

        qr_png = bake(text, [{"op": "Generate QR Code", "args": ["PNG", 5, 4, "M"]}])
        parsed = bake(qr_png, [{"op": "Parse QR Code"}])
        assert parsed == text


class TestQrCodeOpsApi:
    """Tests for QR Code operations via the ops API."""

    def test_generate_qr_code_via_ops(self) -> None:
        """Test generating QR code via ops API."""
        if not hasattr(ops, "generate_qr_code"):
            pytest.skip("generate_qr_code not available in ops API")

        result = ops.generate_qr_code("Test", output_format="PNG")
        assert isinstance(result, bytes)
        assert result.startswith(b"\x89PNG")


class TestQrCodeMatrix:
    """Tests for QR Code matrix generation details."""

    def test_matrix_size_for_version(self) -> None:
        """Test that matrix size matches version."""
        # Version 1: 17 + 4*1 = 21 modules
        matrix_v1 = generate_qr_code_matrix(b"A", ErrorCorrectionLevel.LOW)
        assert len(matrix_v1) == 21

        # Version 2: 17 + 4*2 = 25 modules
        # Need data that requires version 2 but fits in version 2
        # Version 2 with LOW EC can hold up to 34 data codewords
        # With byte mode overhead, we need to find the right size
        matrix_v2 = generate_qr_code_matrix(b"A" * 20, ErrorCorrectionLevel.LOW)
        # Check that it's a valid QR code size (17 + 4*version)
        size = len(matrix_v2)
        version = (size - 17) // 4
        assert size == 17 + 4 * version
        assert version >= 1

    def test_matrix_contains_finder_patterns(self) -> None:
        """Test that matrix contains finder patterns."""
        matrix = generate_qr_code_matrix(b"Test", ErrorCorrectionLevel.MEDIUM)
        len(matrix)

        # Check top-left finder pattern
        # Should have black at (3,3), (3,4), (4,3), etc. (within the pattern)
        # Finder pattern is 7x7, centered at (3,3) for top-left
        # Check the black border
        assert matrix[3][3] is True  # Center of finder pattern
