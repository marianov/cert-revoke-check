import os
import requests
import datetime
import pandas as pd
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Function to download CRL from URL
def download_crl(url, filename):
    response = requests.get(url)
    with open(filename, 'wb') as f:
        f.write(response.content)

# Function to extract CRL number from crl content
def extract_crl_number(crl):
    crl_number = crl.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_NUMBER).value.crl_number
    return crl_number

# Function to get CRL creation time and next update time from crl content
def get_crl_info(crl):
    creation_time = crl.last_update_utc
    next_update_time = crl.next_update_utc
    return creation_time, next_update_time

# Function to count certificates in the CRL from crl content
def count_certs_in_crl(crl):
    cert_count = len(crl)
    return cert_count

# Function to compare CRLs and list newly revoked certs
def compare_crls(old_crl, new_crl):
    old_crl_number = extract_crl_number(old_crl)
    new_crl_number = extract_crl_number(new_crl)

    if old_crl_number == new_crl_number:
        print("No new CRL entries.")
        return

    revoked_certs = [revoked_cert.serial_number for revoked_cert in new_crl]
    print(f"Newly revoked certs ({len(revoked_certs)}):")
    #print(revoked_certs)

# Function to load CRL content into memory and parse it
def load_crl(filename):
    with open(filename, 'rb') as f:
        crl_content = f.read()
    crl = x509.load_der_x509_crl(crl_content, default_backend())
    return crl


# Function to list revoked certs from target list
def get_revoked_certs(crl, serial_numbers):
    revoked_certs = []
    #import ipdb; ipdb.set_trace()
    for serial_number in serial_numbers:
        # compare serial numbers in CRL with hex serial numbers in target list
        if any(hex(revoked_cert.serial_number) == "0x%s" % serial_number for revoked_cert in crl):
            print(serial_number+" found")
            revoked_certs.append(serial_number)
    return revoked_certs

# Main function
def main():
    # Download CRL
    # CRL for Entrust EV certs:
    #crl_url = "http://crl.entrust.net/level1m.crl"

    # CRL for Entrust OV certs:
    crl_url = "http://crl.entrust.net/level1k.crl"

    crl_filename = "level1k.crl"
    download_crl(crl_url, crl_filename)

    # Load CRL content into memory
    crl = load_crl(crl_filename)

    # Extract CRL number
    crl_number = extract_crl_number(crl)
    print(f"CRL number: {crl_number}. Number of revocations: {len(crl)}")

    # Get CRL creation time and next update time
    creation_time, next_update_time = get_crl_info(crl)
    print(f"CRL creation time: {creation_time}")
    print(f"Next update time: {next_update_time}")

    # Copy CRL to a new file with timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
    new_crl_filename = f"{crl_number}-{timestamp}.crl"
    os.rename(crl_filename, new_crl_filename)

    # Infer previous CRL filename
    previous_crl_number = crl_number - 1
    previous_crl_files = [f for f in os.listdir() if f.startswith(str(previous_crl_number))]
    if not previous_crl_files:
        print("Previous CRL file not found. Skipping comparison.")
    else:
        previous_crl_filename = previous_crl_files[0]
        old_crl = load_crl(previous_crl_filename)
        compare_crls(old_crl, crl)

    # Read serial numbers from Excel file
    targets_filename = "targets.xlsx"
    serial_numbers = []
    if not os.path.exists(targets_filename):
        print("Excel file not found. Skipping reading serial numbers.")
    else:
        df = pd.read_excel(targets_filename)
        serial_numbers = df["CERT_SN"].tolist()

    print("Target serial numbers: %s" % serial_numbers )

    # List revoked certs from target list
    revoked_targets = get_revoked_certs(crl, serial_numbers)
    print(f"Revoked certs from target list ({len(revoked_targets)}):")

    # update the rows of the target file with matching revocations
    df.loc[df["CERT_SN"].isin(revoked_targets), "revoked" ] = True
    df.to_excel(targets_filename, sheet_name="revoked", index=False)

    #import ipdb; ipdb.set_trace()

if __name__ == "__main__":
    main()
