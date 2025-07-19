import pefile
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs7
from datetime import datetime

def parse_certificate(cert: x509.Certificate):
    def name_to_str(name):
        return ", ".join([f"{attr.oid._name}: {attr.value}" for attr in name])

    return {
        "subject": name_to_str(cert.subject),
        "issuer": name_to_str(cert.issuer),
        "valid_from": cert.not_valid_before,
        "valid_until": cert.not_valid_after,
        "serial_number": cert.serial_number,
        "is_self_signed": cert.issuer == cert.subject
    }

def extract_signature(pe):
    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    if security_dir.VirtualAddress == 0:
        print("[-] No digital signature found in this file.")
        return

    signature_offset = security_dir.VirtualAddress
    signature_size = security_dir.Size

    print(f"[+] Digital Signature found at offset {hex(signature_offset)}, size: {signature_size} bytes")

    sig_data = bytes(pe.write()[signature_offset + 8 : signature_offset + signature_size]) # skip 8-byte WIN_CERTIFICATE header

    if sig_data[:2] != b'\x30\x82':  # Check if it looks like ASN.1 DER (optional)
        print("[-] Signature data doesn't start like a DER-encoded structure.")
        return

    try:
        signed_data = pkcs7.load_der_pkcs7_certificates(sig_data)
        print(f"[+] Found {len(signed_data)} certificate(s):\n")

        for idx, cert in enumerate(signed_data):
            parsed = parse_certificate(cert)
            print(f"Certificate #{idx + 1}")
            print(f"  - Subject     : {parsed['subject']}")
            print(f"  - Issuer      : {parsed['issuer']}")
            print(f"  - Valid From  : {parsed['valid_from']}")
            print(f"  - Valid Until : {parsed['valid_until']}")
            print(f"  - Serial No.  : {parsed['serial_number']}")
            print(f"  - Self-signed : {'Yes' if parsed['is_self_signed'] else 'No'}\n")

    except Exception as e:
        print(f"[-] Failed to parse PKCS#7 signature: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python ce.py <path_to_pe_file>")
        sys.exit(1)

    pe_path = sys.argv[1]
    try:
        pe = pefile.PE(pe_path, fast_load=True)
        extract_signature(pe)
    except Exception as e:
        print(f"[-] Failed to parse PE file: {e}")