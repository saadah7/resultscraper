#!/usr/bin/env python3
"""
Osmania Result Finder (form-submitting version)

From the main results index page, follow each result link, detect the input form,
submit your roll number, and report only those links that return a valid result.

Example:
  python finder.py "https://www.osmania.ac.in/examination-results.php" 161022733073 --max-follow 300
"""

import argparse
import re
import time
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import certifi
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------- Config ----------------
HEADERS = {"User-Agent": "Mozilla/5.0 (result-finder)"}
REQUEST_TIMEOUT = 30
DEFAULT_MAX_FOLLOW = 250
COURTESY_DELAY = 0.15

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

def build_session(verify_path):
    retry = Retry(
        total=3,
        backoff_factor=0.3,
        status_forcelist=[502, 503, 504],
        allowed_methods=["GET", "HEAD", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)

    s = requests.Session()
    s.headers.update(HEADERS)
    s.verify = verify_path
    s.mount("https://", adapter)
    s.mount("http://", adapter)
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

def looks_like_positive(html_text: str, roll: str) -> bool:
    # Positive if the roll shows up and no negative phrase is detected
    if str(roll) in html_text and not looks_like_negative(html_text, roll):
        return True
    # Some result pages may show "Result", "Marks", "GPA", etc.
    if re.search(r"\b(result|marks|sgpa|cgpa|grade|subject)\b", html_text, re.IGNORECASE):
        if not looks_like_negative(html_text, roll):
            return True
    return False

# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser(description="Find Osmania result links that return a valid result for your roll.")
    ap.add_argument("index_url", help="e.g., https://www.osmania.ac.in/examination-results.php")
    ap.add_argument("roll", help="Your roll / hall ticket number, e.g., 161022733073")
    ap.add_argument("--max-follow", type=int, default=DEFAULT_MAX_FOLLOW, help="Limit links followed (politeness).")
    ap.add_argument("--delay", type=float, default=COURTESY_DELAY, help="Delay between requests (seconds).")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification (only if needed).")
    args = ap.parse_args()

    verify_arg = False if args.insecure else certifi.where()
    if args.insecure:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    session = build_session(verify_arg)

    # 1) Fetch index and collect links
    print(f"Fetching index: {args.index_url}")
    idx = session.get(args.index_url, timeout=REQUEST_TIMEOUT)
    idx.raise_for_status()

    soup = BeautifulSoup(idx.text, "html.parser")
    anchors = soup.find_all("a", href=True)
    links: List[Tuple[str, str]] = []  # (text, absolute_url)

    for a in anchors:
        text = a.get_text(" ", strip=True) or ""
        href = urljoin(idx.url, a["href"])
        links.append((text, href))

    print(f"Found {len(links)} links on index page.")

    # 2) Follow each link, detect and submit form
    matches: List[str] = []
    seen = set()

    for i, (text, href) in enumerate(links, start=1):
        if len(seen) >= args.max_follow:
            break
        if href in seen:
            continue
        seen.add(href)

        # quick skip: ignore obvious non-result links (anchors, mailto, javascript)
        if href.startswith("javascript:") or href.startswith("mailto:") or href.endswith(("#",)):
            continue

        try:
            r = session.get(href, timeout=REQUEST_TIMEOUT)
        except requests.exceptions.SSLError as e:
            print(f"[{i}] TLS issue on {href}: {e}")
            continue
        except Exception:
            continue

        if r.status_code != 200 or not r.text:
            continue

        forms = parse_forms(r.url, r.text)
        if not forms:
            # some result pages may redirect to a dedicated JSP (like the one you shared)
            # if this page itself looks like a result form with JS, we’d need Selenium (out of scope here)
            time.sleep(args.delay)
            continue

        # submit to the first form that has a likely roll field
        hit = False
        for form in forms:
            if not form.roll_field_name:
                continue
            resp = submit_form(session, form, args.roll)
            if not resp or resp.status_code != 200:
                continue

            body = resp.text or ""
            if looks_like_positive(body, args.roll):
                matches.append(href)
                hit = True
                break
            # If it’s the exact negative phrase, we skip quietly
        time.sleep(args.delay)

    # 3) Output
    # de-dupe while preserving order
    deduped = []
    seen_out = set()
    for u in matches:
        if u not in seen_out:
            deduped.append(u)
            seen_out.add(u)

    if deduped:
        print("\nResult links where your roll is present:")
        for u in deduped:
            print(u)
    else:
        print("\nNo matching result links found.")

    with open("matches.txt", "w", encoding="utf-8") as f:
        for u in deduped:
            f.write(u + "\n")
    print("Saved to matches.txt")

if __name__ == "__main__":
    main()
