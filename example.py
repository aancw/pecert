import json

from pecert import extract_certs


def main():
    pe_file_path = "/Users/petruknisme/Downloads/malware/digisign.exe"  # Replace with the actual path to your PE file

    try:
        # Get certificates as a list of dictionaries (default)
        certificates_dict = extract_certs(pe_file_path)
        if certificates_dict:
            print("--- Certificates (Dictionary) ---")
            print(f"Found {len(certificates_dict)} certificate(s):")
            for i, cert_data in enumerate(certificates_dict):
                print(f"\nCertificate #{i + 1}")
                print(f"  Subject:")
                for key, value in cert_data['subject'].items():
                    print(f"    - {key}: {value}")
                print(f"  Issuer:")
                for key, value in cert_data['issuer'].items():
                    print(f"    - {key}: {value}")
        else:
            print("No digital signature found or failed to extract certificates.")

        print("\n" + "=" * 40 + "\n")

        # Get certificates as a JSON string
        certificates_json = extract_certs(pe_file_path, output_format="json")
        if json.loads(certificates_json):
            print("--- Certificates (JSON) ---")
            print(certificates_json)
        else:
            print(
                "No digital signature found or failed to extract certificates (JSON)."
            )

    except FileNotFoundError:
        print(f"Error: File not found at {pe_file_path}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
