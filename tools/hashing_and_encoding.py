import hashlib
import zlib
import base64


def hash_bytes(data_bytes):
    algorithms = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224",
                  "sha3-256", "sha3-384", "sha3-512", "blake2b", "blake2s"]

    results = {}
    for algo in algorithms:
        h = hashlib.new(algo)
        h.update(data_bytes)
        results[algo] = h.hexdigest()

    # Add CRC32 separately
    results["crc32"] = format(zlib.crc32(data_bytes) & 0xFFFFFFFF, '08x')

    return results


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


def encode_string(text):
    data = base64.b64encode(text.encode("unicode_escape"))
    data = data.decode("unicode_escape")
    result = {"plaintext": text, "data": data}
    return result


def decode_string(data):
    try:
        text = base64.b64decode(data)
        text = text.decode("unicode_escape")
        result = {"data": data, "plaintext": text}
    except:
        result = {"data": "Invalid base64-encoded string", "plaintext": ""}

    return result

