"""Tests for attestation module — mirrors the TypeScript vitest suite."""

import hashlib
import os
import struct

import pytest

from venice_e2ee.attestation import derive_eth_address, verify_attestation


# Known test vector: private key = 1 -> well-known Ethereum address
# address = 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf
PRIVKEY_1_ADDRESS = bytes.fromhex("7e5f4552091a69125d5dfcb7b8c2659029395bdf")

# secp256k1 generator point (pubkey for privkey=1, uncompressed)
GENERATOR_HEX = (
    "04"
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)


def _build_fake_quote(
    *,
    td_attributes: bytes = b"\x00" * 8,
    report_data: bytes = b"\x00" * 64,
    tee_type: int = 0x00000081,
) -> str:
    """Build a minimal TDX quote with the given fields at correct offsets."""
    # Header: 48 bytes (teeType at offset 4 as uint32LE)
    header = bytearray(48)
    struct.pack_into("<I", header, 4, tee_type)

    # TDX body up to report_data end
    # tdAttributes at body+120, reportData at body+520
    body_size = 520 + 64  # need to reach end of reportData
    body = bytearray(body_size)
    body[120 : 120 + len(td_attributes)] = td_attributes
    body[520 : 520 + len(report_data)] = report_data

    return (bytes(header) + bytes(body)).hex()


class TestDeriveEthAddress:
    def test_known_vector(self):
        """Private key = 1 produces known Ethereum address."""
        addr = derive_eth_address(GENERATOR_HEX)
        assert addr == PRIVKEY_1_ADDRESS

    def test_without_04_prefix(self):
        addr = derive_eth_address(GENERATOR_HEX[2:])  # 128 hex chars, no 04
        assert addr == PRIVKEY_1_ADDRESS

    def test_with_0x_prefix(self):
        addr = derive_eth_address("0x" + GENERATOR_HEX)
        assert addr == PRIVKEY_1_ADDRESS

    def test_rejects_invalid_key(self):
        with pytest.raises(ValueError, match="Invalid uncompressed"):
            derive_eth_address("abcd")


class TestVerifyAttestation:
    @pytest.fixture
    def nonce(self):
        return os.urandom(32)

    def _make_response(self, nonce: bytes, *, debug: bool = False, use_sha256_nonce: bool = False) -> dict:
        """Build a fake attestation response that passes all checks."""
        signing_key = GENERATOR_HEX
        eth_addr = PRIVKEY_1_ADDRESS

        # REPORTDATA: address[20] || zeros[12] || nonce[32]
        nonce_for_report = hashlib.sha256(nonce).digest() if use_sha256_nonce else nonce
        report_data = eth_addr + b"\x00" * 12 + nonce_for_report

        td_attrs = bytearray(8)
        if debug:
            td_attrs[0] = 0x01

        return {
            "signing_key": signing_key,
            "nonce": nonce.hex(),
            "model": "test-model",
            "intel_quote": _build_fake_quote(
                td_attributes=bytes(td_attrs),
                report_data=report_data,
            ),
            "server_verification": {
                "tdx": {"valid": True},
                "signingAddressBinding": {"bound": True},
                "nonceBinding": {"bound": True},
            },
        }

    @pytest.mark.asyncio
    async def test_valid_attestation(self, nonce):
        resp = self._make_response(nonce)
        result = await verify_attestation(resp, nonce)
        assert result.nonce_verified is True
        assert result.signing_key_bound is True
        assert result.debug_mode is False
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_sha256_nonce(self, nonce):
        resp = self._make_response(nonce, use_sha256_nonce=True)
        result = await verify_attestation(resp, nonce)
        assert result.nonce_verified is True
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_debug_mode_rejected(self, nonce):
        resp = self._make_response(nonce, debug=True)
        result = await verify_attestation(resp, nonce)
        assert result.debug_mode is True
        assert any("DEBUG" in e for e in result.errors)

    @pytest.mark.asyncio
    async def test_wrong_nonce(self, nonce):
        resp = self._make_response(nonce)
        wrong_nonce = os.urandom(32)
        result = await verify_attestation(resp, wrong_nonce)
        assert result.nonce_verified is False
        assert any("nonce" in e.lower() for e in result.errors)

    @pytest.mark.asyncio
    async def test_no_signing_key(self, nonce):
        resp = self._make_response(nonce)
        del resp["signing_key"]
        result = await verify_attestation(resp, nonce)
        assert any("signing key" in e.lower() for e in result.errors)

    @pytest.mark.asyncio
    async def test_no_intel_quote(self, nonce):
        resp = self._make_response(nonce)
        del resp["intel_quote"]
        result = await verify_attestation(resp, nonce)
        assert any("intel_quote" in e for e in result.errors)

    @pytest.mark.asyncio
    async def test_invalid_nonce_length(self):
        result = await verify_attestation({}, b"short")
        assert any("nonce length" in e for e in result.errors)

    @pytest.mark.asyncio
    async def test_server_tdx_failure(self, nonce):
        resp = self._make_response(nonce)
        resp["server_verification"]["tdx"] = {"valid": False, "error": "test failure"}
        result = await verify_attestation(resp, nonce)
        assert result.server_tdx_valid is False
        assert any("Server TDX" in e for e in result.errors)
