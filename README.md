# pecert

A simple and efficient Python tool to extract digital certificate information from PE (Portable Executable) files.

## Features

- Extract certificate information from PE files (`.exe`, `.dll`, etc.).
- Output in both human-readable text and JSON formats.
- Can be used as a command-line tool or as a Python library.
- Takes a direct, lightweight approach to parsing, making it fast and focused.

## Demo

![pecert demo](poc.gif)

## Approach

`pecert` efficiently extracts digital certificates from PE files by combining the strengths of two powerful libraries:

*   **`pefile`**: Used to quickly and accurately locate the `IMAGE_DIRECTORY_ENTRY_SECURITY` data directory, which points to the embedded digital signature within the PE file.
*   **Manual Extraction & `cryptography`**: Since `pefile` focuses on PE structure and doesn't offer built-in certificate parsing, `pecert` takes a direct approach. It manually extracts the raw signature bytes from the PE file based on `pefile`'s pointers, then passes these raw bytes to the `cryptography` library for robust PKCS#7 certificate parsing.

This focused methodology ensures precise and lightweight certificate extraction, complementing `pefile`'s strengths by providing robust certificate content parsing.

## Installation

You can install `pecert` using pip:

```bash
pip install .
```

Or, if you are using `uv`:

```bash
uv pip install .
```

## Usage

### Command-Line Interface

The primary command-line tool is `pecert`.

**Basic Usage:**

```bash
pecert /path/to/your/file.exe
```

**JSON Output:**

To get the output in JSON format, use the `-o json` or `--output json` flag:

```bash
pecert /path/to/your/file.exe -o json
```

### Library Usage

You can also use `pecert` as a library in your own Python scripts. The `extract_certs` function returns a list of dictionaries by default, but can also return a JSON string.

**Get a list of dictionaries (default):**

```python
from pecert import extract_certs

certificates_list = extract_certs("path/to/your/file.exe")
for cert in certificates_list:
    print(cert['subject']['commonName'])
```

**Get a JSON string:**

```python
from pecert import extract_certs

certificates_json = extract_certs("path/to/your/file.exe", output_format='json')
print(certificates_json)
```

**Example (`example.py`):**

```python
from pecert import extract_certs
import json

def main():
    pe_file_path = "path/to/your/pe_file.exe"  # Replace with the actual path to your PE file

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

        print("\n" + "="*40 + "\n")

        # Get certificates as a JSON string
        certificates_json = extract_certs(pe_file_path, output_format='json')
        if json.loads(certificates_json):
            print("--- Certificates (JSON) ---")
            print(certificates_json)
        else:
            print("No digital signature found or failed to extract certificates (JSON).")


    except FileNotFoundError:
        print(f"Error: File not found at {pe_file_path}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.