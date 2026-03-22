"""
utility_tools.py
================
General-purpose utility tools for the Cyber Toolkit.

Functions:
  Hashing:
    - hash_string(text)        → hash a string using all common algorithms
    - hash_bytes(data_bytes)   → hash raw bytes using all common algorithms

  Encoding:
    - encode_string(text)      → Base64 encode a string
    - decode_string(data)      → Base64 decode a string

  Networking:
    - allocate_subnets(base_network, host_requirements) → VLSM subnet allocation
"""

# ─────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────

import base64
import hashlib
import ipaddress
import math
import re
import zlib


# ─────────────────────────────────────────────
# Hashing
# ─────────────────────────────────────────────

def hash_bytes(data_bytes: bytes) -> dict:
    """
    Hash raw bytes using all common cryptographic and checksum algorithms.

    Returns a dict of { algorithm_name: hex_digest }.
    """
    algorithms = [
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
        "sha3_224", "sha3_256", "sha3_384", "sha3_512",
        "blake2b", "blake2s",
    ]

    results = {}

    for algo in algorithms:
        h = hashlib.new(algo)
        h.update(data_bytes)
        results[algo] = h.hexdigest()

    # CRC32 is not in hashlib — computed separately
    results["crc32"] = format(zlib.crc32(data_bytes) & 0xFFFFFFFF, "08x")

    return results


def hash_string(text: str) -> dict:
    """
    Hash a plain-text string using all common cryptographic and checksum algorithms.

    Returns a dict of { algorithm_name: hex_digest }.
    """
    data = text.encode("utf-8")

    results = {
        # ── Legacy (still widely used) ────────────────────────────────────────
        "MD5":       hashlib.md5(data).hexdigest(),
        "SHA1":      hashlib.sha1(data).hexdigest(),

        # ── SHA-2 family ──────────────────────────────────────────────────────
        "SHA224":    hashlib.sha224(data).hexdigest(),
        "SHA256":    hashlib.sha256(data).hexdigest(),
        "SHA384":    hashlib.sha384(data).hexdigest(),
        "SHA512":    hashlib.sha512(data).hexdigest(),

        # ── SHA-3 family ──────────────────────────────────────────────────────
        "SHA3-224":  hashlib.sha3_224(data).hexdigest(),
        "SHA3-256":  hashlib.sha3_256(data).hexdigest(),
        "SHA3-384":  hashlib.sha3_384(data).hexdigest(),
        "SHA3-512":  hashlib.sha3_512(data).hexdigest(),

        # ── BLAKE2 family ─────────────────────────────────────────────────────
        "BLAKE2b":   hashlib.blake2b(data).hexdigest(),
        "BLAKE2s":   hashlib.blake2s(data).hexdigest(),

        # ── Checksum (non-crypto) ─────────────────────────────────────────────
        "CRC32":     format(zlib.crc32(data) & 0xFFFFFFFF, "08x"),
    }

    return results


# ─────────────────────────────────────────────
# Encoding / Decoding
# ─────────────────────────────────────────────

def encode_string(text: str) -> dict:
    """
    Base64 encode a plain-text string.

    Returns:
      { "plaintext": original_string, "data": base64_encoded_string }
    """
    encoded = base64.b64encode(text.encode("unicode_escape")).decode("unicode_escape")
    return {"plaintext": text, "data": encoded}


def decode_string(data: str) -> dict:
    """
    Base64 decode an encoded string.

    Returns:
      { "data": original_encoded_string, "plaintext": decoded_string }

    If the input is not valid Base64, returns an error message in "data".
    """
    try:
        decoded = base64.b64decode(data).decode("unicode_escape")
        return {"data": data, "plaintext": decoded}
    except Exception:
        return {"data": "Invalid base64-encoded string", "plaintext": ""}


# ─────────────────────────────────────────────
# Subnet Calculator
# ─────────────────────────────────────────────

def allocate_subnets(base_network: str, host_requirements: str) -> list[dict]:
    """
    VLSM (Variable Length Subnet Masking) subnet allocator.

    Allocates subnets from a base network to satisfy a list of host requirements,
    sorted largest-first to minimise wasted address space.

    Args:
      base_network:      CIDR notation e.g. "192.168.1.0/24"
      host_requirements: Comma-separated host counts e.g. "50,20,10"

    Returns a list of allocation dicts:
      [
        {
          "Group":          int,
          "Hosts Required": int,
          "Network":        str,
          "Broadcast":      str,
          "Netmask":        str,
          "Prefix":         str,
          "Usable Range":   str,
          "Usable Count":   int,
        },
        ...
      ]

    Raises ValueError on invalid input or insufficient address space.
    """

    # ── Validate base network ─────────────────────────────────────────────────
    try:
        network = ipaddress.ip_network(base_network, strict=False)
    except ValueError:
        raise ValueError(f"Invalid IP network: {base_network}")

    # ── Validate host requirements string ─────────────────────────────────────
    if not re.fullmatch(r"[0-9,\s]+", host_requirements):
        raise ValueError("Host requirements must be numbers separated by commas (e.g. '50,20,10')")

    # ── Parse and sort requirements descending (largest subnet first) ─────────
    requirements = sorted(
        [int(x.strip()) for x in host_requirements.split(",") if x.strip()],
        reverse=True,
    )

    if not requirements:
        raise ValueError("No valid host requirements provided.")

    # ── Allocate subnets greedily ─────────────────────────────────────────────
    allocations = []
    available = [network]   # pool of unallocated address blocks

    for idx, hosts in enumerate(requirements, start=1):
        if hosts <= 0:
            raise ValueError(f"Invalid host requirement: {hosts}. Must be > 0.")

        # Calculate minimum prefix length to fit (hosts + network + broadcast)
        needed_addresses = hosts + 2
        prefix = 32 - math.ceil(math.log2(needed_addresses))

        # Find the first available block large enough to hold this subnet
        for parent in available:
            if parent.prefixlen <= prefix:
                chosen = next(parent.subnets(new_prefix=prefix))

                # Remove the used parent block and return unused siblings to the pool
                available.remove(parent)
                available.extend(
                    s for s in parent.subnets(new_prefix=prefix) if s != chosen
                )
                break
        else:
            raise ValueError(
                f"Not enough address space to allocate {hosts} hosts "
                f"(group {idx}). Consider using a larger base network."
            )

        usable_hosts = list(chosen.hosts())

        allocations.append({
            "Group":          idx,
            "Hosts Required": hosts,
            "Network":        str(chosen.network_address),
            "Broadcast":      str(chosen.broadcast_address),
            "Netmask":        str(chosen.netmask),
            "Prefix":         f"/{chosen.prefixlen}",
            "Usable Range":   f"{usable_hosts[0]} – {usable_hosts[-1]}",
            "Usable Count":   len(usable_hosts),
        })

    return allocations