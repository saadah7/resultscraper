#!/usr/bin/env python3
# Result Finder — locate exam result pages by submitting roll numbers to forms
"""
Osmania Result Finder (form-submitting version)

From the main results index page, follow each result link, detect the input form,
submit your roll number, and report only those links that return a valid result.

Example:
    python finder.py "https://www.osmania.ac.in/examination-results.php" 161022733073 --max-follow 300
"""

import argparse
import concurrent.futures
import re
import ssl
import time
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import certifi
from tqdm import tqdm
import requests
from bs4 import BeautifulSoup
from urllib3.exceptions import SSLError as Urllib3SSLError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
import sys

# ---------------- Config ----------------
HEADERS = {"User-Agent": "Mozilla/5.0 (result-finder)"}
REQUEST_TIMEOUT = 30
DEFAULT_MAX_FOLLOW = 2000  # Increased default to handle large index pages
DEFAULT_WORKERS = 10

# Phrases that indicate "no record" (we’ll check case-insensitively)
NEGATIVE_PHRASES = [
    "is not found",
    "no records found",
    "record not found",
    "invalid hall ticket",
    "no result found",
]

# Candidate input names/ids/placeholders that might be the roll/hall-ticket field
ROLL_HINTS = [
    "roll", "hall", "ticket", "htno", "ht_no", "ht no", "regno", "reg_no", "htnumber",
    "hallticket", "hall_ticket", "seatno", "seat_no", "admissionno", "admission_no",
    "hno", "studentid", "id", "hallu", "ht"  # last few are loose fallbacks
]

# ---------------- Utilities ----------------
def norm(s: str) -> str:
    s = unicodedata.normalize("NFKC", s or "").lower()
    return re.sub(r"\s+", " ", s)

def likely_roll_field(name: str, typ: str, placeholder: str, label: str) -> int:
    """
    Heuristic score: higher = more likely to be the roll/hall-ticket input.
    """
    score = 0
    n = norm(name)
    t = norm(typ)
    p = norm(placeholder)
    l = norm(label)

    # prefer text/tel/number inputs
    if t in ("text", "tel", "number", ""):
        score += 2

    # direct keyword hits
    hay = " ".join([n, p, l])
    for k in ROLL_HINTS:
        if k in hay:
            score += 3

    # common precise names
    if n in ("htno", "hallticket", "hall_ticket", "hall_tkt", "roll", "rollno", "roll_no"):
        score += 4

    # de-prioritize obviously unrelated names
    if any(x in hay for x in ["dob", "date of birth", "captcha", "year", "semester", "month"]):
        score -= 3

    return score

class FallbackTLSAdapter(HTTPAdapter):
    """
    An HTTP adapter that attempts a request with default TLS settings, but falls back
    to forcing TLSv1.2 if a 'TLSV1_ALERT_INTERNAL_ERROR' occurs.
    This handles servers that don't gracefully negotiate down from TLSv1.3.
    """
    def send(self, request, **kwargs):
        try:
            # First attempt with default (modern) TLS settings
            return super().send(request, **kwargs)
        except requests.exceptions.SSLError as e:
            # Check if the error is the specific handshake failure
            is_internal_alert_error = (
                isinstance(e.args[0], Urllib3SSLError) and
                isinstance(e.args[0].reason, ssl.SSLError) and
                'TLSV1_ALERT_INTERNAL_ERROR' in str(e.args[0].reason)
            )

            if is_internal_alert_error:
                # The server might not support TLSv1.3, so we retry and force TLSv1.2
                logging.warning(f"TLS handshake failed for {request.url}, retrying with TLSv1.2...")
                kwargs['ssl_context'] = ssl.create_default_context()
                kwargs['ssl_context'].minimum_version = ssl.TLSVersion.TLSv1_2
                # Forcing a more compatible cipher suite for problematic servers
                kwargs['ssl_context'].set_ciphers(
                    "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH"
                )
                return super().send(request, **kwargs)
            else:
                # Re-raise any other SSL error
                raise

def build_session(verify_path):
    retry = Retry(
        total=3,
        backoff_factor=0.3,
        status_forcelist=[502, 503, 504],
        raise_on_status=False, allowed_methods=None,  # Retry on all methods, including on connection errors
    )
    adapter = FallbackTLSAdapter(max_retries=retry)

    s = requests.Session()
    s.headers.update(HEADERS)
    s.verify = verify_path
    s.mount("https://", adapter)
    return s

@dataclass
class FormInfo:
    method: str
    action_url: str
    inputs: Dict[str, str]     # name -> value (includes hidden defaults)
    roll_field_name: Optional[str]

def extract_label_for_input(soup: BeautifulSoup, input_el) -> str:
    """
    Try to find a human label for an input: associated <label>, or nearby text.
    """
    # <label for="id">
    input_id = input_el.get("id")
    if input_id:
        lab = soup.find("label", attrs={"for": input_id})
        if lab:
            return lab.get_text(" ", strip=True) or ""

    # parent/previous siblings text (rough heuristic)
    prev = input_el.find_previous(string=True)
    if prev and isinstance(prev, str):
        txt = prev.strip()
        if 1 <= len(txt) <= 80:
            return txt
    return ""

def parse_forms(page_url: str, html: str) -> List[FormInfo]:
    soup = BeautifulSoup(html, "html.parser")
    forms: List[FormInfo] = []

    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").upper()
        action_raw = form.get("action") or page_url
        action_url = urljoin(page_url, action_raw)

        # collect inputs (hidden defaults + text fields)
        inputs: Dict[str, str] = {}
        roll_field_name: Optional[str] = None
        best_score = -10

        for inp in form.find_all(["input", "select", "textarea"]):
            name = inp.get("name") or ""
            itype = (inp.get("type") or "").lower()
            placeholder = inp.get("placeholder") or ""
            label = extract_label_for_input(soup, inp)

            # Pre-fill hidden values and defaults
            if inp.name == "input":
                if itype in ("hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file"):
                    # hidden: keep default value if any
                    if name and itype == "hidden":
                        inputs[name] = inp.get("value") or inputs.get(name, "")
                    continue
                # normal input field
                if name:
                    inputs.setdefault(name, inp.get("value") or "")
            elif inp.name == "textarea":
                if name:
                    inputs.setdefault(name, inp.get_text() or "")
            elif inp.name == "select":
                if name:
                    # pick selected option or first option
                    selected = inp.find("option", selected=True)
                    if selected:
                        inputs[name] = selected.get("value") or selected.get_text(strip=True) or ""
                    else:
                        first = inp.find("option")
                        if first:
                            inputs[name] = first.get("value") or first.get_text(strip=True) or ""

            # Heuristic to pick the roll field
            score = likely_roll_field(name, itype, placeholder, label)
            if score > best_score and name:
                best_score = score
                roll_field_name = name

        forms.append(FormInfo(method=method, action_url=action_url, inputs=inputs, roll_field_name=roll_field_name))

    return forms

def submit_form(session: requests.Session, form: FormInfo, roll: str) -> Optional[requests.Response]:
    if not form.roll_field_name:
        return None

    payload = dict(form.inputs)
    payload[form.roll_field_name] = roll

    try:
        if form.method == "POST":
            return session.post(form.action_url, data=payload, timeout=REQUEST_TIMEOUT)
        else:
            return session.get(form.action_url, params=payload, timeout=REQUEST_TIMEOUT)
    except Exception:
        return None

def looks_like_negative(html_text: str, roll: str) -> bool:
    t = norm(html_text)
    # exact message you provided is decisive
    if f'the hall ticket number "{str(roll).lower()}" is not found' in t:
        return True
    for phrase in NEGATIVE_PHRASES:
        if phrase in t:
            return True
    return False

def looks_like_positive(html_text: str, roll: str, keywords: List[str], stream_filters: List[str]) -> bool:
    normalized_text = norm(html_text)
    roll_str = str(roll).lower()

    # 1. Must contain the roll number
    if roll_str not in normalized_text:
        return False

    # 2. Must NOT contain any negative phrases
    if looks_like_negative(html_text, roll): # looks_like_negative already normalizes
        return False

    # 3. Must contain at least one of the provided keywords (if any)
    if keywords and not any(norm(kw) in normalized_text for kw in keywords):
        return False

    # 4. Must contain at least one of the stream filters (if any)
    if stream_filters and not any(norm(sf) in normalized_text for sf in stream_filters):
        return False

    return True

def check_link(
    href: str,
    session: requests.Session,
    roll: str,
    keywords: List[str],
    stream_filters: List[str],
) -> Optional[str]:
    """
    Processes a single link: fetches, parses forms, submits, and checks for a positive result.
    Returns the href if it's a match, otherwise None.
    """
    # quick skip: ignore obvious non-result links (anchors, mailto, javascript)
    if href.startswith("javascript:") or href.startswith("mailto:") or href.endswith(("#",)):
        return None

    try:
        r = session.get(href, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException:
        return None

    if r.status_code != 200 or not r.text:
        return None

    forms = parse_forms(r.url, r.text)
    if not forms:
        # some result pages may redirect to a dedicated JSP (like the one you shared)
        # if this page itself looks like a result form with JS, we’d need Selenium (out of scope here)
        return None

    # submit to the first form that has a likely roll field
    for form in forms:
        if not form.roll_field_name:
            continue
        resp = submit_form(session, form, roll)
        if not resp or resp.status_code != 200:
            continue

        body = resp.text or ""
        if looks_like_positive(body, roll, keywords, stream_filters):
            return href  # It's a match

    return None


# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser(description="Find Osmania result links that return a valid result for your roll.")
    ap.add_argument("index_url", help="e.g., https://www.osmania.ac.in/examination-results.php")
    ap.add_argument("roll", help="Your roll / hall ticket number, e.g., 161022733073")
    ap.add_argument("--max-follow", type=int, default=DEFAULT_MAX_FOLLOW, help="Limit links followed (politeness).")
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Number of concurrent workers for checking links.")
    ap.add_argument("--keywords", type=str, help="Comma-separated keywords that must be present on a result page (e.g., 'grade,marks,total').")
    ap.add_argument("--stream-filter", type=str, help="Comma-separated stream filters (e.g., 'BE,CBCS'). Pages must contain at least one of these.")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification (only if needed).")
    ap.add_argument("--output", "-o", type=str, default="matches.txt", help="Output file to save matching links (default: matches.txt).")
    ap.add_argument("--append", action="store_true", help="Append to the output file instead of overwriting.")
    args = ap.parse_args()

    # Configure logging options
    ap.add_argument("--log-level", type=str, choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO", help="Set logging level.")
    ap.add_argument("--no-color", action="store_true", help="Disable colored output (if any).")

    # Note: argparse was already parsed; re-parse to include new logging args when present.
    # This is a simple approach so we can add logging flags without restructuring the parser.
    args = ap.parse_args()

    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logging.basicConfig(stream=sys.stdout, level=log_level, format="%(levelname)s: %(message)s")
    use_color = not args.no_color

    verify_arg = False if args.insecure else certifi.where()
    if args.insecure:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    keywords = [kw.strip().lower() for kw in args.keywords.split(',')] if args.keywords else []
    stream_filters = [sf.strip().lower() for sf in args.stream_filter.split(',')] if args.stream_filter else []

    session = build_session(verify_arg)

    # 1) Fetch index and collect links
    logging.info(f"Fetching index: {args.index_url}")
    try:
        idx = session.get(args.index_url, timeout=REQUEST_TIMEOUT)
        idx.raise_for_status()
    except requests.exceptions.SSLError as e:
        logging.error(f"SSL certificate verification failed: {e}")
        logging.info("This is often due to an issue with the server's certificate or a network proxy.")
        logging.info("Try running the script again with the --insecure flag, like this:")
        logging.info(f'  python finder.py "{args.index_url}" {args.roll} --insecure')
        return

    soup = BeautifulSoup(idx.text, "html.parser")
    anchors = soup.find_all("a", href=True)
    links: List[Tuple[str, str]] = []  # (text, absolute_url)

    for a in anchors:
        text = a.get_text(" ", strip=True) or ""
        href = urljoin(idx.url, a["href"])
        links.append((text, href))

    logging.info(f"Found {len(links)} links on index page.")

    if len(links) > args.max_follow:
        logging.info(f"NOTE: Will only process the first {args.max_follow} links due to --max-follow limit.")
    else:
        logging.info(f"Processing all {len(links)} links.")

    # 2) Concurrently follow each link, detect and submit form
    matches: List[str] = []
    seen = set()
    links_to_check = []
    for _, href in links:
        if href not in seen:
            seen.add(href)
            links_to_check.append(href)
            if len(links_to_check) >= args.max_follow:
                break

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        # Create a future for each link to be checked
        future_to_url = {
            executor.submit(check_link, href, session, args.roll, keywords, stream_filters): href
            for href in links_to_check
        }

        # Process results as they complete
        for future in tqdm(concurrent.futures.as_completed(future_to_url), total=len(links_to_check), desc="Checking Links"):
            result_href = future.result()
            if result_href:
                matches.append(result_href)


    # 3) Output
    # de-dupe while preserving order
    deduped = []
    seen_out = set()
    for u in matches:
        if u not in seen_out:
            deduped.append(u)
            seen_out.add(u)

    if deduped:
        logging.info("\nResult links where your roll is present:")
        for u in deduped:
            logging.info(u)
    else:
        logging.info("\nNo matching result links found.")

    # Save output to user-specified file (default: matches.txt)
    output_path = args.output or "matches.txt"
    mode = "a" if args.append else "w"
    with open(output_path, mode, encoding="utf-8") as f:
        for u in deduped:
            f.write(u + "\n")
    if args.append:
        logging.info(f"Appended {len(deduped)} result(s) to {output_path}")
    else:
        logging.info(f"Saved to {output_path}")

if __name__ == "__main__":
    main()
