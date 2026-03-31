"""TDX attestation quote parsing and verification.

Implements the same 5-check verification as the TypeScript version:
  1. Debug mode rejection
  2. Client nonce binding (raw or SHA-256)
  3. Signing key Ethereum address binding
  4. Server cross-check consistency
  5. Optional DCAP verification
"""

import hashlib
import hmac
from typing import Any, Callable, Awaitable, Optional

from .crypto import from_hex
from .types import AttestationResult

# TDX quote layout offsets
_TDX_BODY_OFFSET = 48
_TD_ATTRIBUTES_OFFSET = _TDX_BODY_OFFSET + 120  # 168
_TD_ATTRIBUTES_LEN = 8
_REPORT_DATA_OFFSET = _TDX_BODY_OFFSET + 520  # 568
_REPORT_DATA_LEN = 64
_MIN_QUOTE_LEN = _REPORT_DATA_OFFSET + _REPORT_DATA_LEN  # 632

_TDX_TEE_TYPE = 0x00000081


def _keccak256(data: bytes) -> bytes:
    """Compute keccak-256 hash. Requires pycryptodome."""
    try:
        from Crypto.Hash import keccak  # type: ignore[import-untyped]

        h = keccak.new(digest_bits=256)
        h.update(data)
        return h.digest()
    except ImportError:
        raise ImportError(
            "pycryptodome is required for attestation verification. "
            "Install with: pip install 'venice-e2ee[attestation]'"
        ) from None


def derive_eth_address(pub_key_hex: str) -> bytes:
    """Derive Ethereum address from secp256k1 public key.

    address = keccak256(raw_64_bytes)[12:]  (last 20 bytes)

    Args:
        pub_key_hex: hex-encoded public key (uncompressed, with or without 04 prefix)

    Returns:
        20-byte Ethereum address
    """
    hex_str = pub_key_hex
    if hex_str.startswith(("0x", "0X")):
        hex_str = hex_str[2:]
    # Add 04 prefix if given raw 64-byte coordinates
    if len(hex_str) == 128:
        hex_str = "04" + hex_str
    if len(hex_str) != 130 or not hex_str.startswith("04"):
        raise ValueError(
            f"Invalid uncompressed secp256k1 public key (got {len(hex_str)} hex chars)"
        )
    key_bytes = bytes.fromhex(hex_str[2:])  # 64 bytes without 04 prefix
    return _keccak256(key_bytes)[12:]  # last 20 bytes


def _parse_tdx_quote(quote_hex: str) -> tuple[bytes, bytes]:
    """Parse TDX quote, return (td_attributes, report_data)."""
    hex_str = quote_hex
    if hex_str.startswith(("0x", "0X")):
        hex_str = hex_str[2:]
    quote = bytes.fromhex(hex_str)

    if len(quote) < _MIN_QUOTE_LEN:
        raise ValueError(
            f"TDX quote too short: {len(quote)} bytes (need >= {_MIN_QUOTE_LEN})"
        )

    # teeType is uint32LE at offset 4
    tee_type = int.from_bytes(quote[4:8], "little")
    if tee_type != _TDX_TEE_TYPE:
        raise ValueError(f"Not a TDX quote: teeType=0x{tee_type:x} (expected 0x81)")

    td_attributes = quote[_TD_ATTRIBUTES_OFFSET : _TD_ATTRIBUTES_OFFSET + _TD_ATTRIBUTES_LEN]
    report_data = quote[_REPORT_DATA_OFFSET : _REPORT_DATA_OFFSET + _REPORT_DATA_LEN]
    return td_attributes, report_data


async def verify_attestation(
    response: dict[str, Any],
    client_nonce: bytes,
    dcap_verifier: Optional[Callable[[bytes], Awaitable[dict[str, Any]]]] = None,
) -> AttestationResult:
    """Verify a Venice TEE attestation response.

    Always runs v1 binding checks:
      1. Parse TDX quote, reject debug mode
      2. Verify client nonce in REPORTDATA bytes 32-63 (raw or SHA-256)
      3. Verify signing key's Ethereum address in REPORTDATA bytes 0-19
      4. Cross-check server's own verification results
      5. Optional full DCAP verification (if dcap_verifier provided)

    Args:
        response: Full attestation endpoint JSON response
        client_nonce: The 32 raw nonce bytes sent to the endpoint
        dcap_verifier: Optional async function for full DCAP verification

    Returns:
        AttestationResult with per-check pass/fail and error list
    """
    errors: list[str] = []
    nonce_verified = False
    signing_key_bound = False
    debug_mode = False
    server_tdx_valid: bool | None = None
    dcap: dict[str, Any] | None = None

    if len(client_nonce) != 32:
        errors.append(f"Invalid client nonce length: {len(client_nonce)} (expected 32)")
        return AttestationResult(
            nonce_verified=nonce_verified,
            signing_key_bound=signing_key_bound,
            debug_mode=debug_mode,
            server_tdx_valid=server_tdx_valid,
            errors=errors,
        )

    signing_key = response.get("signing_key") or response.get("signing_public_key")
    if not signing_key:
        errors.append("No signing key in attestation response")
        return AttestationResult(
            nonce_verified=nonce_verified,
            signing_key_bound=signing_key_bound,
            debug_mode=debug_mode,
            server_tdx_valid=server_tdx_valid,
            errors=errors,
        )

    # Server-side cross-check
    sv = response.get("server_verification", {})
    if sv:
        tdx_result = sv.get("tdx", {})
        server_tdx_valid = tdx_result.get("valid") if tdx_result else None
        if tdx_result and not tdx_result.get("valid", True):
            errors.append(
                f"Server TDX verification failed: {tdx_result.get('error', 'unknown reason')}"
            )

    # Client-side quote checks
    intel_quote = response.get("intel_quote")
    if not intel_quote:
        errors.append("No intel_quote in attestation response — cannot verify client-side")
        return AttestationResult(
            nonce_verified=nonce_verified,
            signing_key_bound=signing_key_bound,
            debug_mode=debug_mode,
            server_tdx_valid=server_tdx_valid,
            errors=errors,
        )

    try:
        td_attributes, report_data = _parse_tdx_quote(intel_quote)
    except ValueError as e:
        errors.append(f"Failed to parse TDX quote: {e}")
        return AttestationResult(
            nonce_verified=nonce_verified,
            signing_key_bound=signing_key_bound,
            debug_mode=debug_mode,
            server_tdx_valid=server_tdx_valid,
            errors=errors,
        )

    # Check 1: Debug mode
    debug_mode = bool(td_attributes[0] & 0x01)
    if debug_mode:
        errors.append("TEE is running in DEBUG mode — attestation cannot be trusted")

    # Check 2: Nonce binding (raw first, then SHA-256)
    nonce_in_report = report_data[32:64]
    if hmac.compare_digest(nonce_in_report, client_nonce):
        nonce_verified = True
    else:
        hashed_nonce = hashlib.sha256(client_nonce).digest()
        if hmac.compare_digest(nonce_in_report, hashed_nonce):
            nonce_verified = True
        else:
            errors.append("Nonce verification failed: client nonce not found in REPORTDATA")

    # Check 3: Signing key -> Ethereum address binding
    try:
        expected_address = derive_eth_address(signing_key)
        address_in_report = report_data[:20]
        signing_key_bound = hmac.compare_digest(address_in_report, expected_address)
        if not signing_key_bound:
            errors.append(
                "Signing key not bound to TEE: Ethereum address mismatch in REPORTDATA"
            )
    except Exception as e:
        errors.append(f"Failed to verify signing key binding: {e}")

    # Check 4: Cross-check server binding results
    if sv.get("signingAddressBinding"):
        sab = sv["signingAddressBinding"]
        if signing_key_bound != sab.get("bound"):
            errors.append(
                f"Signing key binding inconsistency: client={signing_key_bound}, server={sab.get('bound')}"
            )
    if sv.get("nonceBinding"):
        nb = sv["nonceBinding"]
        if nonce_verified != nb.get("bound"):
            errors.append(
                f"Nonce binding inconsistency: client={nonce_verified}, server={nb.get('bound')}"
            )

    # Check 5: Full DCAP verification (optional)
    if dcap_verifier and intel_quote:
        quote_hex = intel_quote[2:] if intel_quote.startswith("0x") else intel_quote
        try:
            dcap = await dcap_verifier(bytes.fromhex(quote_hex))
            status = dcap.get("status", "")
            if status == "Revoked":
                errors.append("DCAP verification: TCB status is Revoked")
            elif status in ("OutOfDate", "OutOfDateConfigurationNeeded"):
                errors.append(
                    f"DCAP verification: TCB status is {status} — platform firmware may need updating"
                )
        except Exception as e:
            errors.append(f"DCAP verification failed: {e}")

    return AttestationResult(
        nonce_verified=nonce_verified,
        signing_key_bound=signing_key_bound,
        debug_mode=debug_mode,
        server_tdx_valid=server_tdx_valid,
        dcap=dcap,
        errors=errors,
    )
