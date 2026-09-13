import requests


def check_security_headers(url):
    security_headers = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security"
    ]

    try:
        response = requests.get(url, timeout=10)
    except requests.exceptions.RequestException as e:
        return {
            "error": str(e)
        }

    results = {}
    for header in security_headers:
        results[header] = header in response.headers

    return results


def check_xss(base_url, uid, pw):
    session = requests.Session()

    login_data = {
        "uid": uid,
        "pw": pw
    }

    try:
        login_response = session.get(f"{base_url}/login", params=login_data, timeout=10)

        if uid not in login_response.text:
            return {
                "error": "Login failed",
                "vulnerable": None
            }

        xss_payload = "<script>alert('XSS')</script>"
        snippet_data = {
            "snippet": xss_payload
        }
        response = session.get(f"{base_url}/newsnippet2", params=snippet_data, timeout=10)

        vulnerable = xss_payload in response.text
        return {
            "payload": xss_payload,
            "vulnerable": vulnerable
        }

    except requests.exceptions.RequestException as e:
        return {
            "error": f"Request failed: {e}",
            "vulnerable": None
        }


def check_sql_injection(url):
    sql_error_indicators = [
        "sql syntax",
        "mysql_fetch",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sqlite3.operationalerror",
        "you have an error in your sql syntax"
    ]
    test_url = url + "'"

    try:
        response = requests.get(test_url, timeout=10)
        for indicator in sql_error_indicators:
            if indicator in response.text.lower():
                return {
                    "vulnerable": True,
                    "matched_indicator": indicator,
                    "tested_url": test_url
                }

        return {
            "vulnerable": False,
            "matched_indicator": None,
            "tested_url": test_url
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": f"Request failed: {e}",
            "vulnerable": None,
            "matched_indicator": None,
            "tested_url": test_url
        }


def run_full_scan(target_url, uid, pw):
    results = {}

    results["security_headers"] = check_security_headers(target_url)
    results["xss"] = check_xss(target_url, uid, pw)

    sql_test_target = f"{target_url}/homepage?uid={uid}"
    results["sql_injection"] = check_sql_injection(sql_test_target)

    return results


if __name__ == "__main__":
    target_url = "https://google-gruyere.appspot.com/629575711259638391912692181903840619385"
    uid = input("Enter test account username: ")
    pw = input("Enter test account password: ")

    scan_results = run_full_scan(target_url, uid, pw)

    print("\n--- Security Headers ---")
    headers_result = scan_results["security_headers"]
    if "error" in headers_result:
        print(f"[!] Could not check headers: {headers_result['error']}")
    else:
        for header, present in headers_result.items():
            status = "[+]" if present else "[-]"
            print(f"{status} {header}")

    print("\n--- XSS ---")
    xss_result = scan_results["xss"]
    if "error" in xss_result:
        print(f"[!] Could not test XSS: {xss_result['error']}")
    elif xss_result["vulnerable"]:
        print(f"[!] XSS vulnerability found with payload: {xss_result['payload']}")
    else:
        print("[+] No XSS vulnerability detected (payload was sanitized or blocked)")

    print("\n--- SQL Injection ---")
    sql_result = scan_results["sql_injection"]
    if "error" in sql_result:
        print(f"[!] Could not test SQL Injection: {sql_result['error']}")
    elif sql_result["vulnerable"]:
        print(f"[!] SQL Injection vulnerability found! Matched indicator: {sql_result['matched_indicator']}")
    else:
        print("[+] No SQL Injection vulnerability detected")