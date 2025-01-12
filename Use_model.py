import re
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
import tldextract
import requests
import whois
import pandas as pd
import pickle
import requests
from tkinter import messagebox
# Import định nghĩa lớp từ file TrainingMSNB.py
from TrainingMSNB import MSNBNCH, load_model

# Các hàm kiểm tra URL
def check_ip_in_url(url):
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    return -1 if ip_pattern.search(url) else 1

def check_url_length(url):
    length = len(url)
    if length < 54:
        return 1
    elif 54 <= length <= 75:
        return 0
    return -1

def check_url_shortening(url):
    shortening_services = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd']
    parsed_url = tldextract.extract(url).registered_domain
    return -1 if parsed_url in shortening_services else 1

def check_at_symbol(url):
    return -1 if "@" in url else 1

def check_redirect_with_double_slash(url):
    last_occurrence = url.rfind("//")
    if url.startswith("http://") and last_occurrence > 6:
        return -1
    elif url.startswith("https://") and last_occurrence > 7:
        return -1
    return 1

def check_dash_in_domain(url):
    domain = urlparse(url).netloc
    return -1 if '-' in domain else 1

def check_subdomain(url):
    ext = tldextract.extract(url)
    num_dots = ext.subdomain.count('.')
    if num_dots == 0:
        return 1
    elif num_dots == 1:
        return 0
    return -1

def get_certificate_info(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        cert_age = (datetime.now() - not_before).days
        return cert_age, not_after
    except Exception:
        return None, None

def get_domain_expiry_date(url):
    try:
        domain = urlparse(url).netloc
        whois_info = whois.whois(domain)
        expiry_date = whois_info.expiration_date
        if isinstance(expiry_date, list):
            return expiry_date[0]
        return expiry_date
    except Exception:
        return None

def get_favicon_url(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=3)
        if response.status_code == 200:
            parsed_url = urlparse(response.url)
            return f"{parsed_url.scheme}://{parsed_url.netloc}/favicon.ico"
    except Exception:
        pass
    return None

def check_favicon_source(favicon_url, domain):
    parsed_favicon = urlparse(favicon_url).netloc
    parsed_domain = urlparse(domain).netloc
    return -1 if parsed_favicon != parsed_domain else 1

def check_port_usage(domain, port):
    try:
        socket.create_connection((domain, port), timeout=2)
        return 1
    except Exception:
        return -1

def check_https_token_in_domain(url):
    return -1 if "https" in urlparse(url).netloc else 1


#API key from Google Browsing API
API_KEY = 'AIzaSyByDtEx6GmhVytASu27TYhYuehi2s_Qp8s'
# URL endpoint of Google Safe Browsing API
API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

def check_url_safebrowsing(url):
    #payload (sent data) according to requested format of API
    payload = {
        'client': {
            'clientId': 'yourcompanyname',
            'clientVersion': '1.0',

        },
        'threatInfo':{
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [
                {'url': url}
            ]
        }
    }



    response = requests.post(API_URL, params={'key': API_KEY}, json=payload)

    if response.status_code == 200:
        result = response.json()
        if 'matches' in result:
            print(result)
            return False
        else:
            return True
    else:
        return None

def extract_features(url):
    features = {}
    
    domain = urlparse(url).netloc

    features['IP_Check'] = check_ip_in_url(url)
    features['URL_Length_Check'] = check_url_length(url)
    features['Shortening_Check'] = check_url_shortening(url)
    features['At_Symbol_Check'] = check_at_symbol(url)
    features['Redirect_Check'] = check_redirect_with_double_slash(url)
    features['Dash_Check'] = check_dash_in_domain(url)
    features['Subdomain_Check'] = check_subdomain(url)
    
    cert_age, _ = get_certificate_info(url)
    features['Certificate_Age'] = cert_age if cert_age is not None else -1
    
    domain_expiry_date = get_domain_expiry_date(url)
    features['Domain_Expiry_Date'] = 1 if domain_expiry_date is not None else -1
    
    favicon_url = get_favicon_url(domain)
    features['Favicon_Check'] = check_favicon_source(favicon_url, domain) if favicon_url else 0

    features['Port_Check'] = check_port_usage(domain, 80) if check_port_usage(domain, 80) == 1 else check_port_usage(domain, 443)
    features['HTTPS_Token_Check'] = check_https_token_in_domain(url)
    
    return features

def predict_url(url, model):
    features = extract_features(url)
    features_df = pd.DataFrame([features])
    
    prediction = model.predict(features_df)
    return prediction[0]



# Load blacklist từ file hoặc khởi tạo blacklist mới
try:
    with open('D:/Downloads/Dataset1/blacklist.pkl', 'rb') as f:
        blacklist = pickle.load(f)
except FileNotFoundError:
    blacklist = set()

# Hàm thêm URL vào blacklist và lưu lại vào file
def add_to_blacklist(url):
    blacklist.add(url)
    with open('D:/Downloads/Dataset1/blacklist.pkl', 'wb') as f:
        pickle.dump(blacklist, f)

# Hàm kiểm tra URL trong blacklist
def is_url_blacklisted(url):
    return url in blacklist

def main():
    model = load_model('D:/Downloads/Dataset1/model.pkl')
    input_url = input("Nhập URL để kiểm tra: ")
    
    if is_url_blacklisted(input_url):
        print("URL nằm trong blacklist.")
        result = 0  # Giả sử kết quả là phishing nếu URL trong blacklist
    else:
        gsb_result = check_url_safebrowsing(input_url)
        model_result = predict_url(input_url, model)
        
        if gsb_result is None:
            print("Không thể truy cập Google Safe Browsing API.")
            result = model_result
        else:
            result = 1 if gsb_result else 0
            print("Kết quả:", "Benign" if result == 1 else "Phishing")
        
        if gsb_result is not None and result != model_result:
            features = extract_features(input_url)
            features_df = pd.DataFrame([features])
            model.fit(features_df, [result])
            print("Mô hình đã được cập nhật.")
        
        if result == 0:  # Thêm URL vào blacklist nếu kết quả là phishing
            add_to_blacklist(input_url)

if __name__ == "__main__":
    main()
