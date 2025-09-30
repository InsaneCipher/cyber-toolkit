import hashlib
import zlib


def hash_string(text):
    """
    Hashes the input string using commonly used algorithms.
    """
    results = {}
    data = text.encode()

    # Legacy but still common
    results["MD5"] = hashlib.md5(data).hexdigest()
    results["SHA1"] = hashlib.sha1(data).hexdigest()

    # SHA-2 family
    results["SHA224"] = hashlib.sha224(data).hexdigest()
    results["SHA256"] = hashlib.sha256(data).hexdigest()
    results["SHA384"] = hashlib.sha384(data).hexdigest()
    results["SHA512"] = hashlib.sha512(data).hexdigest()

    # SHA-3 family
    results["SHA3-224"] = hashlib.sha3_224(data).hexdigest()
    results["SHA3-256"] = hashlib.sha3_256(data).hexdigest()
    results["SHA3-384"] = hashlib.sha3_384(data).hexdigest()
    results["SHA3-512"] = hashlib.sha3_512(data).hexdigest()

    # BLAKE2 family
    results["BLAKE2b"] = hashlib.blake2b(data).hexdigest()
    results["BLAKE2s"] = hashlib.blake2s(data).hexdigest()

    # Non-crypto but common (checksums)
    results["CRC32"] = format(zlib.crc32(data) & 0xFFFFFFFF, '08x')

    return results
