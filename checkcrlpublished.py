import time
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import pytz
import datetime

# URL for the Entrust L1M CRL
CRL_URL = "http://crl.entrust.net/level1m.crl"

# Initial state
previous_crl_number = None

def get_crl(url):
    response = requests.get(url)
    response.raise_for_status()  # Ensure we notice bad responses
    return x509.load_der_x509_crl(response.content, default_backend()), response.content

def save_crl_to_file(crl_data, crl_number):
    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    filename = f"{crl_number}-{timestamp}.crl"
    with open(filename, 'wb') as f:
        f.write(crl_data)
    print(f"Saved CRL to {filename}")

def main():
    global previous_crl_number

    while True:
        try:
            crl, crl_data = get_crl(CRL_URL)
            crl_number = crl.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_NUMBER).value.crl_number
            issue_date = crl.last_update

            # Ensure the issue_date is in UTC
            issue_date_utc = issue_date.replace(tzinfo=pytz.UTC)
            issue_date_str = issue_date_utc.strftime("%Y-%m-%d %H:%M:%S %Z")

            if crl_number == previous_crl_number:
                print(".", end="", flush=True)
            else:
                print(f"\nCRL Number: {crl_number}, Issued: {issue_date_str}")
                save_crl_to_file(crl_data, crl_number)
                previous_crl_number = crl_number

        except Exception as e:
            print(f"\nError: {e}")

        time.sleep(30)

if __name__ == "__main__":
    main()
