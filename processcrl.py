import os
import subprocess
import datetime
import pandas as pd

# Function to download CRL from URL
def download_crl(url, filename):
    os.system(f"curl -s -o {filename} {url}")

# Function to extract CRL number using OpenSSL
def extract_crl_number(filename):
    output = subprocess.check_output(["openssl", "crl", "-in", filename, "-noout", "-crlnumber"]).decode("utf-8").strip()
    crl_number = None
    if output.startswith("crlNumber="):
        crl_number_hex = output.split("=")[1].strip()
        crl_number = int(crl_number_hex, 16)  # Convert from hexadecimal to decimal
    return crl_number

# Function to get CRL creation time and next update time
def get_crl_info(filename):
    output = subprocess.check_output(["openssl", "crl", "-inform", "DER", "-in", filename, "-noout", "-lastupdate", "-nextupdate"]).decode("utf-8")
    lines = output.split("\n")
    creation_time = lines[0].split("=")[1].strip()
    next_update_time = lines[1].split("=")[1].strip()
    return creation_time, next_update_time

# Function to get the number of certificates in the CRL
def count_certs_in_crl(filename):
    output = subprocess.check_output(["openssl", "crl", "-inform", "DER", "-in", filename, "-noout", "-text"]).decode("utf-8")
    cert_count = output.count("Serial Number:")
    return cert_count

# Function to compare CRLs and list newly revoked certs
def compare_crls(old_crl_file, new_crl_file):
    if not os.path.exists(old_crl_file):
        print("Previous CRL file not found. Skipping comparison.")
        return

    output = subprocess.check_output(["openssl", "crl", "-inform", "DER", "-in", old_crl_file, "-crlnumber", "-noout"]).decode("utf-8")
    old_crl_number = int(output.split("=")[1], 16)
    output = subprocess.check_output(["openssl", "crl", "-inform", "DER", "-in", new_crl_file, "-crlnumber", "-noout"]).decode("utf-8")
    new_crl_number = int(output.split("=")[1], 16)

    if old_crl_number == new_crl_number:
        print("No new CRL entries.")
        return

    output = subprocess.check_output(["openssl", "crl", "-inform", "DER", "-in", new_crl_file, "-noout", "-text"]).decode("utf-8")
    revoked_certs = []
    for line in output.split("\n"):
        if "Revocation Date" in line:
            revoked_certs.append(line.split(":")[1].strip())
    print(f"Newly revoked certs ({len(revoked_certs)}):")
    print("\n".join(revoked_certs))

# Function to load CRL content into memory
def load_crl(filename):
    with open(filename, "rb") as file:
        crl_content = file.read()
    return crl_content

# Function to read serial numbers from Excel file
def read_serial_numbers(filename):
    if not os.path.exists(filename):
        print("Excel file not found. Skipping reading serial numbers.")
        return []
    df = pd.read_excel(filename)
    return df["Serial Number"].tolist()

# Function to list revoked certs from target list
def list_revoked_certs(crl_content, serial_numbers):
    revoked_certs = []
    for serial_number in serial_numbers:
        if f"Serial Number: {serial_number}" in crl_content.decode("utf-8"):
            revoked_certs.append(serial_number)
    print(f"Revoked certs from target list ({len(revoked_certs)}):")
    print(revoked_certs)

# Main function
def main():
    # Download CRL
    crl_url = "http://crl.entrust.net/level1m.crl"
    crl_filename = "level1m.crl"
    download_crl(crl_url, crl_filename)

    # Extract CRL number
    crl_number = extract_crl_number(crl_filename)
    print(f"CRL number: {crl_number}")

    # Get CRL creation time and next update time
    creation_time, next_update_time = get_crl_info(crl_filename)
    print(f"CRL creation time: {creation_time}")
    print(f"Next update time: {next_update_time}")

    # Copy CRL to a new file with timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
    new_crl_filename = f"{crl_number}-{timestamp}.crl"
    os.rename(crl_filename, new_crl_filename)

    # Infer previous CRL filename
    previous_crl_number = crl_number - 1
    previous_crl_filename = f"{previous_crl_number}-*.crl"
    previous_crl_files = [f for f in os.listdir() if f.startswith(str(previous_crl_number))]
    if not previous_crl_files:
        print("Previous CRL file not found. Skipping comparison.")
    else:
        previous_crl_filename = previous_crl_files[0]
        compare_crls(previous_crl_filename, new_crl_filename)

    # Load CRL content into memory
    crl_content = load_crl(new_crl_filename)

    # Read serial numbers from Excel file
    targets_filename = "targets.xlsx"
    serial_numbers = read_serial_numbers(targets_filename)

    # List revoked certs from target list
    list_revoked_certs(crl_content, serial_numbers)

    # Count number of certificates in the CRL
    cert_count = count_certs_in_crl(new_crl_filename)
    print(f"Number of certificates in the current CRL: {cert_count}")

if __name__ == "__main__":
    main()
