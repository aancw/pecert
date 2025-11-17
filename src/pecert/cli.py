import argparse
import json
from . import extract_certs

def main():
    parser = argparse.ArgumentParser(description="Extracts digital certificates from PE files.")
    parser.add_argument("pe_file", help="Path to the PE file.")
    parser.add_argument("-o", "--output", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    args = parser.parse_args()

    if args.output == "json":
        certs_json = extract_certs(args.pe_file, output_format='json')
        print(certs_json)
    else: # Default to text format
        certs = extract_certs(args.pe_file, output_format='dict')
        if not certs:
            print("[-] No digital signature found in this file or failed to parse.")
            return

        print(f"[+] Found {len(certs)} certificate(s):\n")
        for idx, cert_data in enumerate(certs):
            print(f"Certificate #{idx + 1}")
            print(f"  - Subject     :")
            for key, value in cert_data['subject'].items():
                print(f"    - {key}: {value}")
            print(f"  - Issuer      :")
            for key, value in cert_data['issuer'].items():
                print(f"    - {key}: {value}")
            print(f"  - Valid From  : {cert_data['valid_from']}")
            print(f"  - Valid Until : {cert_data['valid_until']}")
            print(f"  - Serial No.  : {cert_data['serial_number']}")
            print(f"  - Self-signed : {'Yes' if cert_data['is_self_signed'] else 'No'}\n")

if __name__ == "__main__":
    main()
