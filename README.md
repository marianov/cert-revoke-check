# Certificate Revocation List (CRL) Analysis Script

This Python script is designed to analyze Certificate Revocation Lists (CRLs) obtained from a given URL. It provides functionality to download the CRL, extract information such as the CRL number, creation time, next update time, count the number of certificates in the CRL, and compare it with a previous CRL if available. Additionally, it can read serial numbers from an Excel file and list revoked certificates from the target list.

## Features

- Downloads CRL from a specified URL.
- Extracts CRL number, creation time, and next update time.
- Copies CRL to a new file with timestamp.
- Compares the current CRL with the previous CRL (if available) and lists newly revoked certificates.
- Loads CRL content into memory.
- Reads serial numbers from an Excel file and lists revoked certificates from the target list.
- Counts the number of certificates in the current CRL.

## Prerequisites

- Python 3.x
- OpenSSL
- pandas library (for reading Excel files)

## Usage

1. Clone the repository or download the script (`crl_analysis.py`) to your local machine.
2. Ensure that Python 3.x and OpenSSL are installed on your system.
3. Install the pandas library by running `pip install pandas`.
4. Run the script using `python crl_analysis.py`.
5. Follow the on-screen prompts to provide necessary inputs and view the analysis results.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
