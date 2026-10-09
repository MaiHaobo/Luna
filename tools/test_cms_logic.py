#!/usr/bin/env python3
"""
Validates the CMS structure that `CMSSigner.swift` emits.

WHY A PYTHON MIRROR
-------------------
The real `CMSSigner` needs `Security.framework` — a `SecIdentity`, a
`SecKey`, `SecKeyCreateSignature` — none of which exist off Apple platforms.
There is no way to run the Swift directly in CI without a macOS runner.

What *can* be verified anywhere is the thing that actually breaks: the ASN.1
structure. This file re-implements the same byte layout in Python, builds it
with a real openssl-generated certificate, and checks two things:

  1. `openssl cms -verify` accepts the detached SignedData, which means the
     field order, tagging and OIDs are all legal PKCS#7.
  2. Every plausible *error* is rejected. These are the mistakes the Swift
     comments warn about — an empty `signedAttrs`, a BIT STRING signature,
     certs wrapped in an extra SEQUENCE, an empty `eContent`. A structure test
     that only proves the happy path would pass just as well if the mirror
     were wrong in the same way as the Swift.

The Python and the Swift are kept in step by hand. That is a real cost, and
the mitigation is that the four negative cases below are exactly the four
mistakes the Swift's header comment enumerates: if someone changes the Swift,
one of these asserts stops matching the intent and the comment stops being
true.

NOT A CRYPTO TEST
-----------------
This does not prove Apple will accept the signature. Apple's verifier has
requirements beyond PKCS#7 — the CodeDirectory binding, the team ID, the
profile match — and none of those can be exercised here. See the header of
`CMSSigner.swift` for what is known and what is assumed.

Usage:
    python3 tools/test_cms_logic.py
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ── ASN.1 primitives, mirroring ASN1Writer.swift ────────────────────────────

TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_SET = 0x31


def tlv(tag, content):
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    length = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + content


def sequence(*children):
    return tlv(TAG_SEQUENCE, b"".join(children))


def set_of(*children):
    # DER requires SET members sorted by encoding.
    return tlv(TAG_SET, b"".join(sorted(children)))


def oid(dotted):
    parts = [int(part) for part in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for arc in parts[2:]:
        stack = [arc & 0x7F]
        arc >>= 7
        while arc:
            stack.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body += bytes(reversed(stack))
    return tlv(TAG_OID, body)


def null():
    return b"\x05\x00"


def integer(value):
    if value == 0:
        return tlv(TAG_INTEGER, b"\x00")
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return tlv(TAG_INTEGER, body)


def octet_string(value):
    return tlv(TAG_OCTET_STRING, value)


def bit_string(value):
    return tlv(TAG_BIT_STRING, b"\x00" + value)


def context_explicit(n, content):
    return tlv(0xA0 | n, content)


def context_implicit(n, content):
    return tlv(0x80 | n, content)


# ── The structure under test ────────────────────────────────────────────────

SHA256_ALGORITHM = sequence(oid("2.16.840.1.101.3.4.2.1"))
RSA_SHA256_ALGORITHM = sequence(oid("1.2.840.113549.1.1.11"), null())
ECDSA_SHA256_ALGORITHM = sequence(oid("1.2.840.10045.4.3.2"))


def build_signed_data(
    code_directory,
    certificate_der,
    issuer_der,
    serial_der,
    signature,
    *,
    signer_extra=(),
    signature_wrapper=octet_string,
    certificate_wrapper=None,
    encap_extra=None,
    signature_algorithm=RSA_SHA256_ALGORITHM,
):
    """Builds a ContentInfo the way `CMSSigner.signedData` should.

    Every keyword argument after `signature` exists to let a test produce a
    *deliberately wrong* variant. The defaults are the correct shape.
    """
    certs = (context_implicit(0, certificate_der)
             if certificate_wrapper is None
             else certificate_wrapper(certificate_der))

    signer_info = sequence(
        integer(1),
        sequence(issuer_der, serial_der),
        SHA256_ALGORITHM,
        signature_algorithm,
        *signer_extra,
        signature_wrapper(signature),
    )

    encap = sequence(*([oid("1.2.840.113549.1.7.1")]
                       + (list(encap_extra) if encap_extra else [])))

    signed_data = sequence(
        integer(1),
        set_of(SHA256_ALGORITHM),
        encap,
        certs,
        set_of(signer_info),
    )

    return sequence(oid("1.2.840.113549.1.7.2"), context_explicit(0, signed_data))


# ── Fixtures ────────────────────────────────────────────────────────────────

def read_tlv(buf, offset):
    tag = buf[offset]
    cursor = offset + 1
    length = buf[cursor]
    cursor += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(buf[cursor:cursor + count], "big")
        cursor += count
    return tag, cursor, length, cursor + length


def split_certificate(der):
    """Returns (issuer_tlv, serial_tlv) taken from the certificate itself.

    This is what `SecCertificateCopyNormalizedIssuerSequence` and
    `SecCertificateCopySerialNumberData` hand back — the *original* DER, which
    is precisely why the Swift uses them rather than re-encoding a Name from
    parsed components.
    """
    _, body, _, _ = read_tlv(der, 0)             # Certificate
    _, tbs, _, _ = read_tlv(der, body)           # TBSCertificate

    cursor = tbs
    if der[cursor] == 0xA0:                      # optional [0] version
        _, _, _, cursor = read_tlv(der, cursor)

    _, _, _, serial_end = read_tlv(der, cursor)
    serial = der[cursor:serial_end]
    cursor = serial_end

    _, _, _, cursor = read_tlv(der, cursor)      # signature AlgorithmIdentifier

    _, _, _, issuer_end = read_tlv(der, cursor)
    issuer = der[cursor:issuer_end]
    return issuer, serial


class Fixture:
    """An openssl-generated certificate, key, and detached signature."""

    def __init__(self, directory, algorithm="rsa"):
        self.directory = Path(directory)
        self.algorithm = algorithm

        if algorithm == "rsa":
            self.key_args = ["-newkey", "rsa:2048", "-nodes"]
        else:
            self.key_args = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                             "-nodes"]

        self.cert_pem = self.directory / "cert.pem"
        self.key_pem = self.directory / "key.pem"

        self.run([
            "openssl", "req", "-x509", *self.key_args,
            "-keyout", str(self.key_pem), "-out", str(self.cert_pem),
            "-days", "365",
            "-subj", "/C=US/O=Luna Test Team/OU=ABCDE12345"
                     "/CN=iPhone Distribution: Luna Test Team",
        ])

        self.cert_der = self.run([
            "openssl", "x509", "-in", str(self.cert_pem), "-outform", "DER",
        ], capture=True)

        self.issuer, self.serial = split_certificate(self.cert_der)

        # A stand-in for the CodeDirectory's bytes. The verifier does not care
        # what the content *is*, only that the signature covers it.
        self.content = bytes([0xFA, 0xDE, 0x0C, 0xC0]) + bytes(range(256)) * 4
        self.content_path = self.directory / "content.bin"
        self.content_path.write_bytes(self.content)

    def run(self, args, capture=False):
        result = subprocess.run(args, capture_output=True, check=True)
        return result.stdout if capture else None

    def sign(self, content=None):
        """Signs `content` with the fixture key, returning the raw signature."""
        path = self.content_path
        if content is not None:
            path = self.directory / "sign_me.bin"
            path.write_bytes(content)
        return self.run([
            "openssl", "dgst", "-sha256", "-sign", str(self.key_pem), str(path),
        ], capture=True)

    def verify(self, blob, content=None):
        """True when openssl accepts `blob` as a detached CMS signature."""
        path = self.directory / "cms.der"
        path.write_bytes(blob)
        content_path = self.content_path
        if content is not None:
            content_path = self.directory / "verify_me.bin"
            content_path.write_bytes(content)

        result = subprocess.run([
            "openssl", "cms", "-verify", "-inform", "DER", "-in", str(path),
            "-content", str(content_path), "-noverify", "-binary",
            "-out", "/dev/null",
        ], capture_output=True)
        output = (result.stdout + result.stderr).decode("utf-8", "replace")
        return "successful" in output


# ── Test harness ────────────────────────────────────────────────────────────

CHECKS = []
FAILURES = []


def check(label, condition, detail=""):
    CHECKS.append(label)
    if condition:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"\n        {detail}" if detail else ""))
        FAILURES.append(label)


# ── Tests ───────────────────────────────────────────────────────────────────

def test_correct_structure_is_accepted(fixture):
    """The shape CMSSigner emits must verify as a detached SignedData."""
    print("\n[1] The correct structure is accepted by openssl")
    blob = build_signed_data(
        fixture.content, fixture.cert_der, fixture.issuer, fixture.serial,
        fixture.sign())
    check("detached SignedData verifies", fixture.verify(blob),
          "openssl rejected the correct structure — the mirror or the "
          "fixture is wrong, and nothing below is meaningful")


def test_algid_encoding():
    """The algorithm identifiers must differ in the way RFC 5758 requires."""
    print("\n[2] Algorithm identifiers")
    # sha256's parameters must be absent. The encoded form is
    # SEQUENCE(11) { OID(9) 2.16.840.1.101.3.4.2.1 } and nothing else — the
    # 11-byte length is what makes that explicit: with a NULL it would be 13.
    check("sha256 AlgorithmIdentifier omits parameters",
          SHA256_ALGORITHM == bytes.fromhex("300b0609608648016503040201"),
          f"got {SHA256_ALGORITHM.hex()}")
    check("sha256 AlgorithmIdentifier is SEQUENCE { OID }",
          SHA256_ALGORITHM[0] == TAG_SEQUENCE and SHA256_ALGORITHM[1] == 0x0B,
          f"got {SHA256_ALGORITHM.hex()}")
    # … while sha256WithRSAEncryption carries a NULL.
    check("sha256WithRSAEncryption carries a NULL parameter",
          RSA_SHA256_ALGORITHM.endswith(b"\x05\x00"),
          f"got {RSA_SHA256_ALGORITHM.hex()}")
    # … and ecdsa-with-SHA256 carries none.
    check("ecdsa-with-SHA256 carries no parameter",
          not ECDSA_SHA256_ALGORITHM.endswith(b"\x05\x00"),
          f"got {ECDSA_SHA256_ALGORITHM.hex()}")


def test_wrong_structures_are_rejected(fixture):
    """Each canonical mistake must produce a structure openssl refuses.

    These are not hypotheticals. Each corresponds to a specific warning in
    the CMSSigner header comment, and each one is a thing a reasonable
    implementation gets wrong.
    """
    print("\n[3] The four canonical mistakes are rejected")

    signature = fixture.sign()
    good = dict(code_directory=fixture.content, certificate_der=fixture.cert_der,
                issuer_der=fixture.issuer, serial_der=fixture.serial,
                signature=signature)

    check("an empty signedAttrs SET is rejected",
          not fixture.verify(build_signed_data(**good, signer_extra=[set_of()])),
          "signedAttrs must be entirely absent, not merely empty")

    check("a BIT STRING signature is rejected",
          not fixture.verify(build_signed_data(**good, signature_wrapper=bit_string)),
          "SignerInfo.signature is an OCTET STRING")

    check("certificates wrapped in an extra SEQUENCE is rejected",
          not fixture.verify(build_signed_data(
              **good, certificate_wrapper=lambda der: context_implicit(0, sequence(der)))),
          "certificates is [0] IMPLICIT; A0 is followed directly by the cert TLV")

    check("an empty eContent OCTET STRING is rejected",
          not fixture.verify(build_signed_data(**good, encap_extra=[octet_string(b"")])),
          "detached means the field is absent, not empty")


def test_length_is_content_independent(fixture):
    """The property MachOCodeSigner's three-step pass depends on.

    The CMS blob's length must not vary with the CodeDirectory's contents —
    only with the certificate and the key. Without this, the length probed in
    step 1 would not match the blob placed in step 3, and the SuperBlob's
    internal offsets would be wrong.
    """
    print("\n[4] CMS length does not depend on the signed content")

    certificate_der = fixture.cert_der
    issuer, serial = fixture.issuer, fixture.serial

    def length_for(content):
        # The signature is fixed-length for a given key, so signing different
        # content produces the same-sized blob.
        signature = fixture.sign(content)
        blob = build_signed_data(
            content, certificate_der, issuer, serial, signature)
        return len(blob), len(signature)

    small = length_for(bytes(64))
    large = length_for(bytes(64 * 1024))

    check("blob length is identical for a 64-byte and a 64 KiB content",
          small[0] == large[0],
          f"{small[0]} vs {large[0]} — a content-dependent length would break "
          f"the three-step signing pass")
    check("signature length is a function of the key, not the content",
          small[1] == large[1] == 256,
          f"RSA-2048 must always produce 256 bytes; got {small[1]} and {large[1]}")


def test_curve_algorithm_identifier(fixture):
    """ECDSA signs with the same structure but a different OID."""
    print("\n[5] ECDSA uses the same shape with its own OID")

    blob = build_signed_data(
        fixture.content, fixture.cert_der, fixture.issuer, fixture.serial,
        fixture.sign(), signature_algorithm=ECDSA_SHA256_ALGORITHM)
    # The signature is RSA here, so verification will fail — that is expected.
    # What is being checked is that the OID is where it belongs and that the
    # structure still parses as far as the signature bytes.
    check("ecdsa-with-SHA256 OID appears in the SignerInfo",
          ECDSA_SHA256_ALGORITHM in blob,
          "the signature algorithm field must carry the ECDSA OID")

    parsed = subprocess.run(
        ["openssl", "asn1parse", "-inform", "DER", "-in", "/dev/stdin"],
        input=blob, capture_output=True)
    text = (parsed.stdout + parsed.stderr).decode("utf-8", "replace")
    check("the ECDSA-variant structure parses as ASN.1",
          ":ecdsa-with-SHA256" in text,
          "openssl could not parse the structure at all")


def test_certificate_splitting(fixture):
    """The issuer and serial come back as complete TLVs, not bare content.

    This is the assumption the Swift makes when it checks the leading tag
    instead of blindly re-tagging. If a future iOS returns bare content here,
    the Swift's fallback branch handles it — but this documents what the
    current API actually does, which is the thing the tests below rely on.
    """
    print("\n[6] Issuer and serial arrive as complete TLVs")
    check("issuer starts with the SEQUENCE tag",
          fixture.issuer[0] == TAG_SEQUENCE,
          f"got 0x{fixture.issuer[0]:02x}; the Swift's fallback would re-wrap it")
    check("serial starts with the INTEGER tag",
          fixture.serial[0] == TAG_INTEGER,
          f"got 0x{fixture.serial[0]:02x}; the Swift's fallback would re-wrap it")
    check("the issuer TLV is not itself wrapped a second time",
          fixture.issuer[1] == 0x69 or fixture.issuer[1] & 0x80 != 0,
          f"length octet 0x{fixture.issuer[1]:02x} looks like a nested header")


def test_team_id_extraction(fixture):
    """The OU really is where the ten-character team ID lives."""
    print("\n[7] Team ID is in the OU, not the O")
    text = subprocess.run(
        ["openssl", "x509", "-in", str(fixture.cert_pem), "-noout",
         "-subject", "-nameopt", "RFC2253"],
        capture_output=True, check=True).stdout.decode()
    check("subject carries OU=ABCDE12345", "OU=ABCDE12345" in text, text.strip())
    check("subject carries O=Luna Test Team",
          "O=Luna Test Team" in text, text.strip())


# ── Entry point ─────────────────────────────────────────────────────────────

def main():
    if shutil.which("openssl") is None:
        print("openssl not found; cannot run CMS structure tests")
        return 1

    print("CMS structure tests")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as directory:
        rsa = Fixture(directory, "rsa")
        test_correct_structure_is_accepted(rsa)
        test_wrong_structures_are_rejected(rsa)
        test_length_is_content_independent(rsa)
        test_curve_algorithm_identifier(rsa)
        test_certificate_splitting(rsa)
        test_team_id_extraction(rsa)

    test_algid_encoding()

    print()
    print("=" * 70)
    if FAILURES:
        print(f"❌ {len(FAILURES)} of {len(CHECKS)} checks failed")
        for failure in FAILURES:
            print(f"   · {failure}")
        return 1
    print(f"✅ all {len(CHECKS)} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
