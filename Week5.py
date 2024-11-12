import requests
import re
from tkinter import messagebox

# API key from Google Browsing API
API_KEY = 'AIzaSyByDtEx6GmhVytASu27TYhYuehi2s_Qp8s'
# URL endpoint of Google Safe Browsing API
API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

# Suspicious URL and email patterns
suspicious_patterns = [r'\.cn/', r'-', r'http://', r'login', r'secure']
suspicious_subject_keywords = [
    r"account\s*suspended", r"urgent", r"verify\s*your\s*account", r"congratulations", r"winner", r"free"
]
suspicious_body_pattern = [
    r"\bverify\b.*\byour\b.*\baccount", r"urgent action required", r"click here to claim your prize",
    r"update your payment information", r"you have won", r"\.cn", r"http://", r"secure"
]

# Function to check URL manually
def manual_check_url(url):
    print(f"Checking URL manually: {url}")
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            messagebox.showwarning("Warning", f"URL seems suspicious due to pattern: '{pattern}'")
            return False
    print("URL seems safe for the user.")
    return True

# Function to check URL with Google Safe Browsing API
def check_url_safebrowsing(url):
    payload = {
        'client': {
            'clientId': 'yourcompanyname',
            'clientVersion': '1.0',
        },
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }

    response = requests.post(API_URL, params={'key': API_KEY}, json=payload)

    if response.status_code == 200:
        result = response.json()
        if 'matches' in result:
            messagebox.showerror("Scam Alert", f"URL {url} is found to be dangerous.")
            return False
        else:
            print(f"URL {url} seems safe.")
            return True
    else:
        print(f"Error: Cannot connect to Google Safe Browsing API. Status code: {response.status_code}")
        return None

# Function to check email subject and body
def check_subject(subject):
    for pattern in suspicious_subject_keywords:
        if re.search(pattern, subject, re.IGNORECASE):
            messagebox.showwarning("Warning", f"Email subject seems suspicious: '{pattern}'")
            return False
    return True

def check_body(body):
    for pattern in suspicious_body_pattern:
        if re.search(pattern, body, re.IGNORECASE):
            messagebox.showwarning("Warning", f"Email body contains suspicious content: '{pattern}'")
            return False
    return True

# Main function to check URL and email
def multi_check(url, email_subject, email_body):
    gg_safe = check_url_safebrowsing(url)
    if gg_safe is None:
        print("Cannot check with Google Safe Browsing API.")
    elif gg_safe:
        print("Proceeding with manual check...")
        if manual_check_url(url):
            print(f"URL {url} seems safe.")
        else:
            messagebox.showwarning("Warning", f"URL {url} seems suspicious after manual check.")
    else:
        messagebox.showerror("Scam Alert", f"URL {url} is identified as dangerous by Google Safe Browsing API.")
    
    # Check email subject if it is not empty or None
    if email_subject:
        subject_safe = check_subject(email_subject)
    else:
        subject_safe = True  # Skip check if email_subject is empty

    # Check email body if it is not empty or None
    if email_body:
        body_safe = check_body(email_body)
    else:
        body_safe = True  # Skip check if email_body is empty

    if subject_safe and body_safe:
        print("Email seems safe.")
    else:
        messagebox.showwarning("Scam Alert", "The email appears to be a scam based on suspicious patterns in the subject or body.")

def main():
    url = input("Enter URL: ").strip()
    subject = input("Enter email subject: ").strip()
    body = input("Enter email content: ").strip()
    multi_check(url, subject, body)

if __name__ == '__main__':
    main()
