#!/usr/bin/env python3

# Author      : Bilal Haider ID (github.com/BilalHaiderID)
# Version     : 0.0.1
# Description : PinHoarder is a Pinterest Mass Image Downloader that lets you collect and save images from Pinterest using simple command-line options.
# DISCLAIMER  : This tool is for educational and research purposes only.
#               The author is not responsible for any misuse or illegal activity.
#               Always ensure you have permission before querying personal data.

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import requests

coloff = "\033[0m"         # NoColour
red = "\033[1;31m"         # Red
green = "\033[1;32m"       # Green
white = "\033[1;37m"       # Blue
blue = "\033[1;34m"        # White

# One session reused across the whole run for cookies/CSRF
SES = requests.Session()

# Headers close to the original script to satisfy Pinterest
PIN_HEADERS_BASE = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 11; 220333QAG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
    "X-APP-VERSION": "ba6e535",
    "X-Pinterest-AppState": "active",
    "X-Pinterest-PWS-Handler": "www/search/[scope].js",
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "application/json, text/javascript, */*, q=0.01",
}

SEARCH_SCOPE = "/search/pins/?rs=typed&q="
DOMAINS_TRY = ["www.pinterest.com", "id.pinterest.com"]  # try global then local


def sanitize_url(u: str) -> str:
    # Unescape Pinterest JSON string-encoded URLs
    return u.replace("\\u0026", "&").replace("\\/", "/")


def safe_name(s: str) -> str:
    # For file names
    return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in s).strip("_")


class PinterestScraper:
    def __init__(self, keyword: str, maxdump: int, outdir: str, download: bool, scrolls: int):
        self.keyword = keyword.strip()
        self.maxdump = int(maxdump)
        self.outdir = outdir
        self.download = download
        self.scrolls = max(1, int(scrolls))
        self.collected = []
        self.seen = set()
        self.now = str(time.time()).replace(".", "")[:-4]
        self.domain_in_use = None

    # ---------------- Public API ----------------
    def run(self):
        os.makedirs(self.outdir, exist_ok=True)
        for domain in DOMAINS_TRY:
            try:
                self.domain_in_use = domain
                self._bootstrap_session()
                self._search_and_paginate()
                if self.collected:
                    break
            except Exception:
                # Try next domain silently; robustness over verbosity
                continue

        if not self.collected:
            print(f"[!] No images found for keyword: {self.keyword}")
            return

        self._save_results()

    # ---------------- Core network flow ----------------
    def _bootstrap_session(self):
        # Prime cookies & CSRFTOKEN similar to original script
        q = urllib.parse.quote(self.keyword)
        url = (
            f"https://{self.domain_in_use}/resource/UserExperienceResource/get/"
            f"?source_url={SEARCH_SCOPE}{q}"
            f"&data={{\"options\":{{\"placement_ids\":[29],\"extra_context\":{{\"search_query\":\"{self.keyword}\"}}}},\"context\":{{}}}}"
            f"&_={self.now}"
        )
        headers = dict(PIN_HEADERS_BASE)
        headers["X-Pinterest-Source-Url"] = f"{SEARCH_SCOPE}{q}"
        SES.get(url, headers=headers, timeout=20)

    def _search_and_paginate(self):
        q = urllib.parse.quote(self.keyword)
        options = {
            "article": "",
            "appliedProductFilters": "---",
            "price_max": None,
            "price_min": None,
            "query": self.keyword,
            "scope": "pins",
            "auto_correction_disabled": "",
            "top_pin_id": "",
            "filters": "",
        }
        data_param = json.dumps({"options": options, "context": {}})
        url = (
            f"https://{self.domain_in_use}/resource/BaseSearchResource/get/"
            f"?source_url={SEARCH_SCOPE}{q}&data={data_param}&_={self.now}"
        )

        headers = dict(PIN_HEADERS_BASE)
        headers["X-Pinterest-Source-Url"] = f"{SEARCH_SCOPE}{q}"

        # Page 1
        link = SES.get(url, headers=headers, timeout=25).text
        self._extract_from_search(link, headers)
        if len(self.collected) >= self.maxdump:
            return

        # Additional pages = "scrolls - 1"
        pages_loaded = 1
        while pages_loaded < self.scrolls and len(self.collected) < self.maxdump:
            bookmarks = re.findall(r'"bookmark":"(.*?)"', link)
            if not bookmarks:
                break
            bookmark = bookmarks[0]
            payload = {
                "data": json.dumps({"options": {**options, "bookmarks": [bookmark]}, "context": {}}),
                "source_url": f"{SEARCH_SCOPE}{q}",
            }
            post_headers = dict(headers)
            csrftoken = SES.cookies.get("csrftoken")
            if csrftoken:
                post_headers["X-CSRFToken"] = csrftoken

            link = SES.post(
                f"https://{self.domain_in_use}/resource/BaseSearchResource/get/",
                params=payload,
                headers=post_headers,
                timeout=25,
            ).text

            self._extract_from_search(link, headers)
            pages_loaded += 1
            if not re.search(r'"bookmark":"', link):
                break

    def _extract_from_search(self, link_text: str, headers: dict):
        # Quick wins: 736/736x thumbs + any 'originals' directly in payload
        for u in re.findall(r'"url":"(.*?)"', link_text):
            u = sanitize_url(u)
            if ("com/736" in u or "com/736x" in u or "originals" in u) and self._add_image(u):
                self._progress_dump()
                if len(self.collected) >= self.maxdump:
                    return

        # Get pin IDs and ask the related feed to fetch 'originals'
        for pin in re.findall(r'"id":"(\d+)"', link_text):
            if len(self.collected) >= self.maxdump:
                return
            if len(pin) == 18:
                self._fetch_related_originals(pin, headers)

    def _fetch_related_originals(self, pin: str, headers: dict):
        # 1 page of related is usually plenty; stop early if we reach maxdump
        nowish = str(time.time()).replace(".", "")[:-4]
        url = (
            f"https://{self.domain_in_use}/resource/RelatedPinFeedResource/get/"
            f"?source_url=/pin/{pin}/&data={{\"options\":{{\"field_set_key\":\"unauth_react\",\"page_size\":12,\"pin\":\"{pin}\",\"source\":\"search\"}},\"context\":{{}}}}"
            f"&_={nowish}"
        )
        local_headers = dict(headers)
        csrftoken = SES.cookies.get("csrftoken")
        if csrftoken:
            local_headers["X-CSRFToken"] = csrftoken
        local_headers["X-Pinterest-Source-Url"] = f"/pin/{pin}/"

        try:
            link = SES.get(url, headers=local_headers, timeout=25).text
        except Exception:
            return

        for u in re.findall(r'"url":"(.*?)"', link):
            u = sanitize_url(u)
            if "originals" in u and self._add_image(u):
                self._progress_dump()
                if len(self.collected) >= self.maxdump:
                    return

        # One extra bookmark page from related (lightweight)
        bks = re.findall(r'"bookmark":"(.*?)"', link)
        if not bks or len(self.collected) >= self.maxdump:
            return
        bookmark = bks[0]
        next_url = (
            f"https://{self.domain_in_use}/resource/RelatedPinFeedResource/get/"
            f"?source_url=/pin/{pin}/&data={{\"options\":{{\"field_set_key\":\"unauth_react\",\"page_size\":12,\"pin\":\"{pin}\",\"source\":\"search\",\"bookmarks\":[\"{bookmark}\"]}},\"context\":{{}}}}"
            f"&_={nowish}"
        )
        try:
            link2 = SES.get(next_url, headers=local_headers, timeout=25).text
        except Exception:
            return
        for u in re.findall(r'"url":"(.*?)"', link2):
            u = sanitize_url(u)
            if "originals" in u and self._add_image(u):
                self._progress_dump()
                if len(self.collected) >= self.maxdump:
                    return

    # ---------------- Helpers ----------------
    def _add_image(self, url: str) -> bool:
        if url not in self.seen:
            self.seen.add(url)
            self.collected.append(url)
            return True
        return False

    def _progress_dump(self):
        print(f"[{green}D U M P I N G{coloff}] --> ({self.keyword}) - {green}{len(self.collected)}{coloff} - {red}/{coloff} - {green}{self.maxdump}{coloff}", end="\r", flush=True)

    def _progress_download(self, current: int):
        print(f"[{green}D O W N L O A D I N G{coloff}] --> ({self.keyword}) - {green}{current}{coloff} - {red}/{coloff} - {green}{min(self.maxdump, len(self.collected))}{coloff}", end="\r", flush=True)

    # ---------------- Output ----------------
    def _save_results(self):
        base = os.path.join(self.outdir, safe_name(self.keyword))
        subset = self.collected[: self.maxdump]

        # Always write links file (even when downloading)
        txt_path = f"{base}.txt"
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(subset))

        # newline after last progress tick
        print()

        if self.download and subset:
            for i, url in enumerate(subset, 1):
                fname = f"{base}_{i}.jpg"
                try:
                    # stream via requests to control timeouts
                    with SES.get(url, stream=True, timeout=30, headers={"User-Agent": PIN_HEADERS_BASE["User-Agent"]}) as r:
                        r.raise_for_status()
                        with open(fname, "wb") as out:
                            for chunk in r.iter_content(chunk_size=8192):
                                if chunk:
                                    out.write(chunk)
                    self._progress_download(i)
                except Exception:
                    # ignore single download failures; continue
                    continue
            print("\n----------------------------------------------------------")  # newline after progress
            print(f"[{green}✓{coloff}] Downloaded images saved in {green}{self.outdir} {coloff} \n----------------------------------------------------------" if any(os.path.isfile(f"{base}_{i}.jpg") for i in range(1, len(subset) + 1))
                  else "[×] Downloading failed for all images.")
        else:
            if subset:
                print("\n----------------------------------------------------------")
                print(f"[{green}✓{coloff}] Links saved to {green}{txt_path}{coloff}")
                print("----------------------------------------------------------\n")
            else:
                print(f"[×] No images collected for {self.keyword}; wrote empty list to {txt_path}")


# ---------------- CLI ----------------
def parse_args():
    parser = argparse.ArgumentParser(
        prog="PinHoarder",
        description="PinHoarder is a Pinterest Mass Image Downloader that lets you collect and save images from Pinterest using simple command-line options.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # Your requested aliases
    parser.add_argument("--kw", "--keywords", dest="keywords",
                        help="Comma-separated keywords, e.g. --kw \"vladimir putin\"")
    parser.add_argument("--kf", "--keywordsfile", dest="keywordsfile",
                        help="Path to a file with one keyword per line")
    parser.add_argument("--max", "--maxdump", dest="maxdump", type=int, default=20,
                        help="Maximum number of images per keyword")
    parser.add_argument("--scroll", type=int, default=1,
                        help="How many times to scroll (additional pages) to load")
    parser.add_argument("-o", "--output", default="dumpimgs",
                        help="Output directory (created if missing)")
    parser.add_argument("-d", "--download", action="store_true",
                        help="Download images (otherwise: only write .txt links)")
    return parser.parse_args()


def load_keywords(args) -> list:
    kws = []
    if args.keywords:
        kws.extend([k.strip() for k in args.keywords.split(",") if k.strip()])
    if args.keywordsfile:
        try:
            with open(args.keywordsfile, "r", encoding="utf-8") as f:
                kws.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"[!] File not found: {args.keywordsfile}")
            sys.exit(1)
    # Deduplicate preserving order
    seen = set()
    ordered = []
    for k in kws:
        if k not in seen:
            seen.add(k)
            ordered.append(k)
    return ordered


def main():
    print("\n")
    args = parse_args()
    keywords = load_keywords(args)
    if not keywords:
        print("[!] No keywords provided. Use --kw or --kf. See --help.")
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    for kw in keywords:
        scraper = PinterestScraper(
            keyword=kw,
            maxdump=args.maxdump,
            outdir=args.output,
            download=args.download,
            scrolls=args.scroll,
        )
        scraper.run()


if __name__ == "__main__":
    main()
