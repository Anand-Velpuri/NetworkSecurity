"""
URL Feature Extractor for Phishing Detection
Extracts 30 features from a given URL matching the schema used by the trained model.
Each feature returns -1 (legitimate), 0 (suspicious), or 1 (phishing).
"""

import re
import socket
import ssl
import whois
import requests
from urllib.parse import urlparse, urlencode
from datetime import datetime, timezone
from bs4 import BeautifulSoup


def _safe_request(url, timeout=5):
    """Safely fetch URL content."""
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }
        response = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        return response
    except Exception:
        return None


def _get_soup(response):
    """Parse HTML response into BeautifulSoup object."""
    try:
        return BeautifulSoup(response.text, "html.parser")
    except Exception:
        return None


def having_IP_Address(url):
    """Check if the URL uses an IP address instead of a domain name."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    # IPv4 pattern
    ipv4 = re.match(
        r"^(\d{1,3}\.){3}\d{1,3}$", hostname
    )
    # IPv6 or hex-based
    ipv6 = re.match(r"^0x[0-9a-fA-F]+", hostname) or hostname.startswith("[")
    if ipv4 or ipv6:
        return 1  # phishing
    return -1  # legitimate


def URL_Length(url):
    """Check the length of the URL."""
    if len(url) < 54:
        return -1  # legitimate
    elif 54 <= len(url) <= 75:
        return 0  # suspicious
    else:
        return 1  # phishing


def Shortining_Service(url):
    """Check if the URL uses a shortening service."""
    shorteners = [
        "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly",
        "t.co", "tinyurl", "tr.im", "is.gd", "cli.gs", "yfrog.com",
        "migre.me", "ff.im", "tiny.cc", "url4.eu", "twit.ac", "su.pr",
        "twurl.nl", "snipurl.com", "short.to", "BudURL.com", "ping.fm",
        "post.ly", "Just.as", "bkite.com", "snipr.com", "fic.kr",
        "loopt.us", "doiop.com", "short.ie", "kl.am", "wp.me",
        "rubyurl.com", "om.ly", "to.ly", "bit.do", "lnkd.in",
        "db.tt", "qr.ae", "adf.ly", "cutt.ly", "rb.gy"
    ]
    url_lower = url.lower()
    for s in shorteners:
        if s.lower() in url_lower:
            return 1  # phishing
    return -1  # legitimate


def having_At_Symbol(url):
    """Check for '@' symbol in URL."""
    if "@" in url:
        return 1  # phishing
    return -1  # legitimate


def double_slash_redirecting(url):
    """Check if '//' appears after the protocol."""
    # Find position of // after the protocol
    pos = url.find("//")
    if pos >= 0:
        after = url[pos + 2:]
        if "//" in after:
            return 1  # phishing
    return -1  # legitimate


def Prefix_Suffix(url):
    """Check if '-' (dash) is present in the domain."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if "-" in hostname:
        return 1  # phishing
    return -1  # legitimate


def having_Sub_Domain(url):
    """Count the dots in the domain to determine subdomain depth."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    # Remove 'www.' for counting
    hostname = hostname.replace("www.", "")
    dot_count = hostname.count(".")
    if dot_count == 1:
        return -1  # legitimate
    elif dot_count == 2:
        return 0  # suspicious
    else:
        return 1  # phishing


def SSLfinal_State(url):
    """Check SSL certificate validity and issuer trust."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            # Check if certificate exists and is valid
            if cert:
                issuer = dict(x[0] for x in cert.get("issuer", []))
                # Trusted issuers
                trusted = [
                    "DigiCert", "Let's Encrypt", "GeoTrust", "Comodo",
                    "Symantec", "GlobalSign", "Sectigo", "Amazon",
                    "Google Trust Services"
                ]
                issuer_org = issuer.get("organizationName", "")
                for t in trusted:
                    if t.lower() in issuer_org.lower():
                        return -1  # legitimate
                return 0  # suspicious
            return 1  # phishing
    except Exception:
        return 1  # phishing (no SSL)


def Domain_registeration_length(url):
    """Check the domain registration duration."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    try:
        w = whois.whois(hostname)
        expiration = w.expiration_date
        creation = w.creation_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        if isinstance(creation, list):
            creation = creation[0]
        if expiration and creation:
            age_days = (expiration - creation).days
            if age_days <= 365:
                return 1  # phishing
            return -1  # legitimate
        return 1
    except Exception:
        return 1  # phishing


def Favicon(url, soup):
    """Check if the favicon is loaded from an external domain."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    try:
        if soup:
            icons = soup.find_all("link", rel=lambda x: x and "icon" in x)
            for icon in icons:
                href = icon.get("href", "")
                if href:
                    icon_parsed = urlparse(href)
                    if icon_parsed.hostname and icon_parsed.hostname != hostname:
                        return 1  # phishing
        return -1  # legitimate
    except Exception:
        return -1


def port_feature(url):
    """Check if a non-standard port is used."""
    parsed = urlparse(url)
    port = parsed.port
    preferred_ports = [80, 443, 8080]
    if port and port not in preferred_ports:
        return 1  # phishing
    return -1  # legitimate


def HTTPS_token(url):
    """Check for 'https' token in the domain part."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if "https" in hostname.lower():
        return 1  # phishing (using https in domain name to deceive)
    return -1  # legitimate


def Request_URL(url, soup):
    """Check the percentage of external objects in the page."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    try:
        if not soup:
            return -1
        total = 0
        external = 0
        for tag in soup.find_all(["img", "video", "audio", "source"]):
            src = tag.get("src", "")
            if src:
                total += 1
                src_parsed = urlparse(src)
                if src_parsed.hostname and src_parsed.hostname != hostname:
                    external += 1
        if total == 0:
            return -1
        ratio = external / total
        if ratio < 0.22:
            return -1  # legitimate
        elif ratio < 0.61:
            return 0  # suspicious
        else:
            return 1  # phishing
    except Exception:
        return -1


def URL_of_Anchor(url, soup):
    """Check the percentage of anchor URLs pointing to different domains."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    try:
        if not soup:
            return 1
        total = 0
        unsafe = 0
        for a in soup.find_all("a"):
            href = a.get("href", "")
            total += 1
            if href in ("#", "", "javascript:void(0)") or href.startswith("javascript:"):
                unsafe += 1
            else:
                href_parsed = urlparse(href)
                if href_parsed.hostname and href_parsed.hostname != hostname:
                    unsafe += 1
        if total == 0:
            return -1
        ratio = unsafe / total
        if ratio < 0.31:
            return -1  # legitimate
        elif ratio < 0.67:
            return 0  # suspicious
        else:
            return 1  # phishing
    except Exception:
        return 1


def Links_in_tags(url, soup):
    """Check the percentage of links in meta/script/link tags."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    try:
        if not soup:
            return 1
        total = 0
        external = 0
        for tag in soup.find_all(["meta", "script", "link"]):
            src = tag.get("href", "") or tag.get("src", "")
            if src:
                total += 1
                src_parsed = urlparse(src)
                if src_parsed.hostname and src_parsed.hostname != hostname:
                    external += 1
        if total == 0:
            return -1
        ratio = external / total
        if ratio < 0.17:
            return -1  # legitimate
        elif ratio < 0.81:
            return 0  # suspicious
        else:
            return 1  # phishing
    except Exception:
        return 1


def SFH(url, soup):
    """Check Server Form Handler."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    try:
        if not soup:
            return 0
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action", "")
            if action in ("", "about:blank"):
                return 1  # phishing
            action_parsed = urlparse(action)
            if action_parsed.hostname and action_parsed.hostname != hostname:
                return 0  # suspicious
        return -1  # legitimate
    except Exception:
        return 0


def Submitting_to_email(soup):
    """Check if the page submits to an email (mailto: in forms)."""
    try:
        if not soup:
            return -1
        html_str = str(soup)
        if "mailto:" in html_str or "mail(" in html_str:
            return 1  # phishing
        return -1  # legitimate
    except Exception:
        return -1


def Abnormal_URL(url):
    """Check if the hostname is present in the URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    try:
        w = whois.whois(hostname)
        if w.domain_name:
            return -1  # legitimate
        return 1  # phishing
    except Exception:
        return 1  # phishing


def Redirect(response):
    """Check the number of redirects."""
    try:
        if response is None:
            return 0
        redirect_count = len(response.history)
        if redirect_count <= 1:
            return -1  # legitimate (was 0 originally)
        elif redirect_count < 4:
            return 0  # suspicious
        else:
            return 1  # phishing
    except Exception:
        return 0


def on_mouseover(soup):
    """Check for onMouseOver to hide the link in status bar."""
    try:
        if not soup:
            return -1
        html_str = str(soup)
        if re.search(r"onmouseover\s*=.*?window\.status", html_str, re.IGNORECASE):
            return 1  # phishing
        return -1  # legitimate
    except Exception:
        return -1


def RightClick(soup):
    """Check if right-click is disabled."""
    try:
        if not soup:
            return -1
        html_str = str(soup)
        if re.search(r"event\.button\s*==\s*2", html_str) or "contextmenu" in html_str.lower():
            return 1  # phishing
        return -1  # legitimate
    except Exception:
        return -1


def popUpWidnow(soup):
    """Check for popups with form fields."""
    try:
        if not soup:
            return -1
        html_str = str(soup)
        if "window.open" in html_str and ("prompt(" in html_str or "input" in html_str.lower()):
            return 1  # phishing
        return -1  # legitimate
    except Exception:
        return -1


def Iframe(soup):
    """Check for iframes."""
    try:
        if not soup:
            return -1
        iframes = soup.find_all("iframe")
        if iframes:
            return 1  # phishing
        return -1  # legitimate
    except Exception:
        return -1


def age_of_domain(url):
    """Check the age of the domain."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    try:
        w = whois.whois(hostname)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            now = datetime.now()
            if creation.tzinfo:
                now = datetime.now(timezone.utc)
            age_months = (now - creation).days / 30
            if age_months >= 6:
                return -1  # legitimate
            return 1  # phishing
        return 1
    except Exception:
        return 1


def DNSRecord(url):
    """Check DNS record for the domain."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    try:
        socket.gethostbyname(hostname)
        return -1  # legitimate (DNS record exists)
    except Exception:
        return 1  # phishing (no DNS record)


def web_traffic(url):
    """Estimate web traffic (simplified – based on whether the site responds quickly)."""
    try:
        response = _safe_request(url, timeout=3)
        if response and response.status_code == 200:
            return -1  # legitimate (likely has traffic)
        return 1  # phishing
    except Exception:
        return 1


def Page_Rank(url):
    """Simplified page rank estimation."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    # Well-known domains get legitimate score
    well_known_tlds = [".gov", ".edu", ".org"]
    for tld in well_known_tlds:
        if hostname.endswith(tld):
            return -1
    # Heuristic: shorter domains with common TLDs tend to have higher rank
    if len(hostname) < 20 and hostname.count(".") <= 2:
        return -1  # likely legitimate
    return 1  # likely phishing


def Google_Index(url):
    """Check if the page is indexed (simplified check)."""
    try:
        response = _safe_request(url, timeout=5)
        if response and response.status_code == 200:
            return -1  # legitimate (accessible, likely indexed)
        return 1  # phishing
    except Exception:
        return 1


def Links_pointing_to_page(soup):
    """Check the number of links pointing to the page."""
    try:
        if not soup:
            return 0
        links = soup.find_all("a")
        if len(links) == 0:
            return 1  # phishing
        elif len(links) <= 2:
            return 0  # suspicious
        else:
            return -1  # legitimate
    except Exception:
        return 0


def Statistical_report(url):
    """Check if the URL matches known phishing patterns."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    suspicious_keywords = [
        "login", "signin", "verify", "account", "update", "secure",
        "banking", "confirm", "password", "credential", "suspend"
    ]
    url_lower = url.lower()
    match_count = sum(1 for kw in suspicious_keywords if kw in url_lower)
    if match_count >= 2:
        return 1  # phishing
    return -1  # legitimate


def extract_features(url):
    """
    Extract all 30 features from a URL.
    Returns a dict with feature names as keys and values as -1, 0, or 1.
    """
    # Ensure URL has scheme
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    # Fetch the page
    response = _safe_request(url)
    soup = _get_soup(response) if response else None

    features = {
        "having_IP_Address": having_IP_Address(url),
        "URL_Length": URL_Length(url),
        "Shortining_Service": Shortining_Service(url),
        "having_At_Symbol": having_At_Symbol(url),
        "double_slash_redirecting": double_slash_redirecting(url),
        "Prefix_Suffix": Prefix_Suffix(url),
        "having_Sub_Domain": having_Sub_Domain(url),
        "SSLfinal_State": SSLfinal_State(url),
        "Domain_registeration_length": Domain_registeration_length(url),
        "Favicon": Favicon(url, soup),
        "port": port_feature(url),
        "HTTPS_token": HTTPS_token(url),
        "Request_URL": Request_URL(url, soup),
        "URL_of_Anchor": URL_of_Anchor(url, soup),
        "Links_in_tags": Links_in_tags(url, soup),
        "SFH": SFH(url, soup),
        "Submitting_to_email": Submitting_to_email(soup),
        "Abnormal_URL": Abnormal_URL(url),
        "Redirect": Redirect(response),
        "on_mouseover": on_mouseover(soup),
        "RightClick": RightClick(soup),
        "popUpWidnow": popUpWidnow(soup),
        "Iframe": Iframe(soup),
        "age_of_domain": age_of_domain(url),
        "DNSRecord": DNSRecord(url),
        "web_traffic": web_traffic(url),
        "Page_Rank": Page_Rank(url),
        "Google_Index": Google_Index(url),
        "Links_pointing_to_page": Links_pointing_to_page(soup),
        "Statistical_report": Statistical_report(url),
    }

    return features
