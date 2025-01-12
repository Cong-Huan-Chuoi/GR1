import re
import ssl
import socket
import whois
import requests
import tldextract
from urllib.parse import urlparse
import csv
from datetime import datetime

# 1. Kiểm tra URL có chứa IP Address
def check_ip_in_url(url):
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    return -1 if ip_pattern.search(url) else 1

# 2. Kiểm tra URL dài
def check_url_length(url):
    length = len(url)
    if length < 54:
        return 1
    elif 54 <= length <= 75:
        return 0
    return -1

# 3. Kiểm tra URL shortening services
def check_url_shortening(url):
    shortening_services = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd']
    parsed_url = tldextract.extract(url).registered_domain
    return -1 if parsed_url in shortening_services else 1

# 4. Kiểm tra @ symbol trong URL
def check_at_symbol(url):
    return -1 if "@" in url else 1

# 5. Kiểm tra redirect với "//" trong URL
def check_redirect_with_double_slash(url):
    last_occurrence = url.rfind("//")
    if url.startswith("http://") and last_occurrence > 6:
        return -1
    elif url.startswith("https://") and last_occurrence > 7:
        return -1
    return 1

# 6. Kiểm tra dấu "-" trong domain
def check_dash_in_domain(url):
    domain = urlparse(url).netloc
    return -1 if '-' in domain else 1

# 7. Kiểm tra subdomain
def check_subdomain(url):
    ext = tldextract.extract(url)
    num_dots = ext.subdomain.count('.')
    if num_dots == 0:
        return 1
    elif num_dots == 1:
        return 0
    return -1

# 8. Kiểm tra HTTPS và lấy thông tin chứng chỉ
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

# 9. Kiểm tra thời gian đăng ký domain
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

# 10. Kiểm tra nguồn favicon
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

# 11. Kiểm tra sử dụng cổng
def check_port_usage(domain, port):
    try:
        socket.create_connection((domain, port), timeout=2)
        return 1
    except Exception:
        return -1

# 12. Kiểm tra token HTTPS trong domain
def check_https_token_in_domain(url):
    return -1 if "https" in urlparse(url).netloc else 1

# Xử lý file CSV
def process_urls(input_csv, output_csv):
    with open(input_csv, mode='r') as infile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames + [
            'IP_Check', 'URL_Length_Check', 'Shortening_Check', 'At_Symbol_Check', 'Redirect_Check', 
            'Dash_Check', 'Subdomain_Check', 'Certificate_Age', 'Domain_Expiry_Date',
            'Favicon_Check', 'Port_Check', 'HTTPS_Token_Check'
        ]

        # Mở file CSV đầu ra
        with open(output_csv, mode='w', newline='') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            count = 0
            # Lặp qua từng dòng trong file CSV đầu vào
            for row in reader:
                url = row['url']
                domain = urlparse(url).netloc

                # Áp dụng các kiểm tra
                row['IP_Check'] = check_ip_in_url(url)
                row['URL_Length_Check'] = check_url_length(url)
                row['Shortening_Check'] = check_url_shortening(url)
                row['At_Symbol_Check'] = check_at_symbol(url)
                row['Redirect_Check'] = check_redirect_with_double_slash(url)
                row['Dash_Check'] = check_dash_in_domain(url)
                row['Subdomain_Check'] = check_subdomain(url)
                
                # Lấy thông tin chứng chỉ SSL và ngày hết hạn đăng ký domain
                cert_age, cert_expiry = get_certificate_info(url)
                domain_expiry_date = get_domain_expiry_date(url)

                # Kiểm tra favicon và cổng
                favicon_url = get_favicon_url(domain)
                favicon_check = check_favicon_source(favicon_url, domain) if favicon_url else None

                row['Certificate_Age'] = 1 if cert_age is not None else -1
                row['Domain_Expiry_Date'] = 1 if domain_expiry_date is not None else -1
                row['Favicon_Check'] = favicon_check if favicon_check is not None else 0

                row['Port_Check'] = check_port_usage(domain, 80) if check_port_usage(domain, 80) == 1 else check_port_usage(domain, 443)
                row['HTTPS_Token_Check'] = check_https_token_in_domain(url)

                # Ghi dòng đã cập nhật vào file CSV đầu ra
                writer.writerow(row)
                print(count)
                count += 1
                

    print(f"Dữ liệu đã xử lý được lưu vào {output_csv}")




process_urls('D:/Downloads/Dataset1/malicious_phish2.csv', 'D:/Downloads/Dataset1/checkdataseturl2.csv')
