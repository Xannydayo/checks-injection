import requests
from bs4 import BeautifulSoup
import re
from tqdm import tqdm

def check_injection(url):
    payloads = ["'", '"', '--', '#', '/*', '*/', ';', ' OR 1=1', ' OR "a"="a', ' OR \'a\'=\'a']
    vulnerable = False

    for payload in tqdm(payloads, desc="Checking payloads for SQL Injection vulnerabilities"):
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                if re.search(r'error|syntax|warning|mysql|sql', soup.text, re.IGNORECASE):
                    print(f"Potential SQL Injection vulnerability found with payload: {payload}")
                    vulnerable = True
                else:
                    print(f"No SQL Injection vulnerability found with payload: {payload}")
            else:
                print(f"Received non-200 status code for payload: {payload}")
        except requests.RequestException as e:
            print(f"Request failed for payload {payload}: {e}")

    if not vulnerable:
        print("No SQL Injection vulnerabilities found after testing all payloads.")

if __name__ == "__main__":
    target_url = input("Enter the URL to check for SQL Injection: ")
    if target_url:
        print(f"Starting SQL Injection check for URL: {target_url}")
        check_injection(target_url)
    else:
        print("No URL provided. Exiting the program.")
