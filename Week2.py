
import requests
import re

#API key from Google Browsing API
API_KEY = 'AIzaSyByDtEx6GmhVytASu27TYhYuehi2s_Qp8s'
# URL endpoint of Google Safe Browsing API
API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
# suspicious URL sample
suspicious_patterns = [
    r'\.cn/',
    r'-',
    r'http://',
    r'login',
    r'secure',
]

#function check by hand
def manual_check_url(url):
    print(f"Check URL: {url}")
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            print(f"Waring: URL seems suspicious'{pattern}'")
            return False
    print("URL seems safe for user.")
    return True

#function to check by Google Safe Browsing API
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
            print(f"URL {url} is a scam URL.")
            print(result)
            return False
        else:
            print(f"URL {url} seems safe.")
            return True
    else:
        print(f"Error. Can not connect to Google Safe Browsing API. Error code: {response.status_code}")
        return None
def main():
    url = input("Write URL: ").strip()
    gg_safe = check_url_safebrowsing(url)
    if gg_safe is None:
        print("cannot check with GSB API.")
    elif gg_safe:
        print("continue to check by hand...")
        if manual_check_url(url):
            print(f"URL {url} seems safe after check by hand.")
        else:
            print(f"URL {url} seems not safe after check by hand.")
    else: 
        print(f"URL {url} is found dangerous by GSB API.")

if __name__ == '__main__':

    main()