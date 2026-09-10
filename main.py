import requests

def check_security_headers(url):
    response = requests.get(url, timeout=10)
    security_headers = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security"
    ]
    results = {}

    for header in security_headers:
        if header in response.headers:
            results[header] = True
        else:
            results[header] = False
    return results


def check_xss(base_url, uid, pw):
    session = requests.Session()

    login_data = {
        "uid": uid,
        "pw": pw
    }
    session.get(f"{base_url}/login", params=login_data)

    xss_payload = "<script>alert('XSS')</script>"
    snippet_data = {
        "snippet": xss_payload
    }
    response = session.get(f"{base_url}/newsnippet2", params=snippet_data)

    vulnerable = xss_payload in response.text
    return {
        "payload": xss_payload,
        "vulnerable": vulnerable
    }


if __name__ == "__main__":
    target_url = "https://google-gruyere.appspot.com/629575711259638391912692181903840619385"

    print("Checking security headers...")
    headers_result = check_security_headers(target_url)
    for header, present in headers_result.items():
        status = "[+]" if present else "[-]"
        print(f"{status} {header}")

    print("\nChecking for XSS vulnerability...")
    uid = input("Enter test account username: ")
    pw = input("Enter test account password: ")
    xss_result = check_xss(target_url, uid, pw)
    if xss_result["vulnerable"]:
        print(f"[!] XSS vulnerability found with payload: {xss_result['payload']}")
    else:
        print("[+] No XSS vulnerability detected (payload was sanitized or blocked)")