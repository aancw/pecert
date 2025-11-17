import json
import warnings

import pefile
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7

# Suppress the specific UserWarning from the cryptography library
warnings.filterwarnings(
    "ignore",
    message="PKCS#7 certificates could not be parsed as DER, falling back to parsing as BER.",
)


def parse_certificate(cert: x509.Certificate):
    def name_to_dict(name):
        d = {}
        for attr in name:
            value = attr.value
            if isinstance(value, bytes):
                try:
                    # Try decoding with UTF-8 first
                    value = value.decode('utf-8')
                except UnicodeDecodeError:
                    # Fallback for non-UTF-8 bytes, e.g., some legacy encodings
                    value = value.decode('latin-1', errors='replace')
            d[attr.oid._name] = value
        return d

    return {
        "subject": name_to_dict(cert.subject),
        "issuer": name_to_dict(cert.issuer),
        "valid_from": cert.not_valid_before_utc.isoformat(), # Convert datetime to ISO format string
        "valid_until": cert.not_valid_after_utc.isoformat(), # Convert datetime to ISO format string
        "serial_number": hex(cert.serial_number), # Convert serial number to hex string
        "is_self_signed": cert.issuer == cert.subject
    }


def extract_certs(pe_file_path, output_format="dict"):
    try:
        pe = pefile.PE(pe_file_path, fast_load=True)
    except pefile.PEFormatError:
        return [] if output_format == "dict" else "[]"

    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]
    if security_dir.VirtualAddress == 0:
        return [] if output_format == "dict" else "[]"

    signature_offset = security_dir.VirtualAddress
    signature_size = security_dir.Size

    sig_data = bytes(
        pe.write()[signature_offset + 8 : signature_offset + signature_size]
    )  # skip 8-byte WIN_CERTIFICATE header

    if sig_data[:2] != b"\x30\x82":  # Check if it looks like ASN.1 DER (optional)
        return [] if output_format == "dict" else "[]"

    try:
        signed_data = pkcs7.load_der_pkcs7_certificates(sig_data)
        certs = [parse_certificate(cert) for cert in signed_data]
        if output_format == 'json':
            return json.dumps(certs, indent=4, ensure_ascii=False)
        return certs
    except Exception:
        return [] if output_format == "dict" else "[]"
