import re


suspicious_subject_keywords = [
    r"account\s*suspended",
    r"urgent",
    r"verify\s*your\s*account",
    r"congratulations",
    r"winner",
    r"free"
]

suspicious_body_pattern = [
    r"\bverify\b.*\byour\b.*\baccount",
    r"urgent action required",
    r"click here to claim your prize",
    r"update your payment information",
    r"you have won",
    r"\.cn",
    r"http://",
    r"secure",
]

def check_subject(subject):
    for pattern in suspicious_subject_keywords:
        if re.search(pattern, subject, re.IGNORECASE):
            #print(f"Waring: The title is suspicious {pattern}.")
            return False
    return True

def check_body(body):
    for pattern in suspicious_body_pattern:
        if re.search(pattern, body, re.IGNORECASE):
            #print(f"Waring: The body is suspicious {pattern}.")
            return False
    return True  
def main():

    subject = input("Email title: ").strip()
    body = input("Email content: ").strip()
    subject_safe = check_subject(subject)
    body_safe = check_body(body)
    if subject_safe and body_safe:
        print("Email seems safe for you.")
    else:
        print("Waring: Email looks like a scam.")

if __name__ == '__main__':
    main()
