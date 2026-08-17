"""
Website Security Scanner - Desktop GUI
--------------------------------------------------
Enter any website URL you own (or have permission to scan), click Scan,
and get a report of common security misconfigurations - which page,
what the issue is, severity, and how to fix it.

Checks performed:
    1. Security headers (CSP, HSTS, X-Frame-Options, etc.)
    2. SSL/TLS certificate health (expiry, protocol version)
    3. Commonly exposed sensitive files (.env, .git/config, backups...)
    4. Cookie security flags (Secure, HttpOnly, SameSite)
    5. CORS misconfiguration
    6. Outdated / known-vulnerable JS libraries (jQuery, Bootstrap, etc.)
    7. Basic information disclosure (server banners, verbose errors)

IMPORTANT / LEGAL:
    Only scan websites you own or have explicit written permission to
    test. Scanning systems without authorization is illegal in most
    countries, regardless of intent. This tool performs passive/light
    checks only - it does not attempt exploitation.

    This is an automated scanner. It CANNOT guarantee 100% accuracy -
    it can produce false positives/negatives and cannot detect business
    logic flaws. Use it as a first-pass helper, not a replacement for
    a professional penetration test.

Run with:
    python security_scanner_gui.py
"""

import re
import ssl
import socket
import threading
import datetime
from urllib.parse import urlparse, urljoin

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import requests
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()  # we intentionally check certs ourselves

TIMEOUT = 8

# ---------------------------------------------------------------------
# Known vulnerable JS library version ranges (illustrative, not exhaustive).
# Real-world usage should also cross-check a live CVE database.
# ---------------------------------------------------------------------
VULNERABLE_LIBS = {
    "jquery": [
        ("<3.5.0", "Vulnerable to XSS via jQuery.htmlPrefilter (CVE-2020-11022/11023). Upgrade to 3.5.0+."),
        ("<3.0.0", "Multiple known XSS/prototype-pollution issues in jQuery 1.x/2.x. Upgrade to latest 3.x."),
    ],
    "bootstrap": [
        ("<4.3.1", "XSS vulnerabilities in tooltip/popover/affix (multiple CVEs). Upgrade to 4.3.1+ or 5.x."),
        ("<3.4.0", "XSS in data-target/data-container attributes. Upgrade to 3.4.0+ or migrate to 5.x."),
    ],
    "angular": [
        ("<1.8.0", "Multiple XSS/sandbox-bypass issues in AngularJS < 1.8.0. Upgrade or migrate off AngularJS (EOL)."),
    ],
    "lodash": [
        ("<4.17.21", "Prototype pollution vulnerabilities (CVE-2020-8203/28500). Upgrade to 4.17.21+."),
    ],
}

FIX_SUGGESTIONS = {
    "hsts": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "csp": "Add a Content-Security-Policy header restricting script/style/img sources to trusted origins.",
    "x-frame-options": "Add header: X-Frame-Options: DENY (or SAMEORIGIN) to prevent clickjacking.",
    "x-content-type-options": "Add header: X-Content-Type-Options: nosniff",
    "referrer-policy": "Add header: Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
    "permissions-policy": "Add a Permissions-Policy header to restrict browser features (camera, mic, geolocation, etc.).",
    "ssl_expiry": "Renew the SSL/TLS certificate before it expires; automate renewal (e.g. Let's Encrypt + certbot).",
    "ssl_protocol": "Disable TLS 1.0/1.1 on the server; only allow TLS 1.2+ (ideally TLS 1.3).",
    "exposed_file": "Block access to this path via server config (nginx/Apache) or remove it from the public webroot.",
    "cookie_secure": "Set the 'Secure' flag on cookies so they're only sent over HTTPS.",
    "cookie_httponly": "Set the 'HttpOnly' flag on cookies to prevent JavaScript (XSS) from reading them.",
    "cookie_samesite": "Set 'SameSite=Lax' or 'SameSite=Strict' on cookies to reduce CSRF risk.",
    "cors": "Avoid 'Access-Control-Allow-Origin: *' combined with credentials. Whitelist specific trusted origins only.",
    "server_banner": "Suppress/minimize the 'Server' and 'X-Powered-By' headers to reduce information disclosure.",
    "verbose_error": "Disable debug/verbose error pages in production; show generic error pages instead.",
    "outdated_lib": "Upgrade the library to the patched version listed in the finding.",
}

COMMON_SENSITIVE_PATHS = [
    ".env", ".git/config", ".git/HEAD", "wp-config.php.bak", "config.php.bak",
    "backup.zip", "backup.sql", ".DS_Store", "web.config", "docker-compose.yml",
    ".htpasswd", "phpinfo.php", "admin/", "server-status", "id_rsa",
]


# ---------------------------------------------------------------------
# Individual check functions - each returns a list of finding dicts
# ---------------------------------------------------------------------
def make_finding(check, severity, page, detail, fix_key=None, custom_fix=None):
    return {
        "check": check,
        "severity": severity,
        "page": page,
        "detail": detail,
        "fix": custom_fix or FIX_SUGGESTIONS.get(fix_key, "Review manually."),
    }


def check_headers(url, resp):
    findings = []
    headers = {k.lower(): v for k, v in resp.headers.items()}

    if "strict-transport-security" not in headers and url.startswith("https"):
        findings.append(make_finding("Missing HSTS", "Medium", url,
                                      "Site does not send a Strict-Transport-Security header.", "hsts"))
    if "content-security-policy" not in headers:
        findings.append(make_finding("Missing CSP", "High", url,
                                      "No Content-Security-Policy header found - increases XSS risk.", "csp"))
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        findings.append(make_finding("Missing X-Frame-Options", "Medium", url,
                                      "Page can potentially be embedded in an iframe (clickjacking risk).",
                                      "x-frame-options"))
    if "x-content-type-options" not in headers:
        findings.append(make_finding("Missing X-Content-Type-Options", "Low", url,
                                      "MIME-sniffing protection header missing.", "x-content-type-options"))
    if "referrer-policy" not in headers:
        findings.append(make_finding("Missing Referrer-Policy", "Low", url,
                                      "No Referrer-Policy header set.", "referrer-policy"))
    if "permissions-policy" not in headers:
        findings.append(make_finding("Missing Permissions-Policy", "Low", url,
                                      "No Permissions-Policy header set.", "permissions-policy"))

    server = headers.get("server")
    if server:
        findings.append(make_finding("Server Banner Disclosure", "Low", url,
                                      f"Server header reveals: '{server}'", "server_banner"))
    powered_by = headers.get("x-powered-by")
    if powered_by:
        findings.append(make_finding("X-Powered-By Disclosure", "Low", url,
                                      f"X-Powered-By header reveals: '{powered_by}'", "server_banner"))

    return findings


def check_cookies(url, resp):
    findings = []
    for cookie in resp.cookies:
        name = cookie.name
        if not cookie.secure:
            findings.append(make_finding(f"Cookie '{name}' missing Secure flag", "Medium", url,
                                          "Cookie can be sent over unencrypted HTTP.", "cookie_secure"))
        httponly = cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")
        if not httponly:
            findings.append(make_finding(f"Cookie '{name}' missing HttpOnly flag", "Medium", url,
                                          "Cookie is readable via JavaScript, increasing XSS impact.",
                                          "cookie_httponly"))
        samesite = cookie.get_nonstandard_attr("SameSite") or cookie.get_nonstandard_attr("samesite")
        if not samesite:
            findings.append(make_finding(f"Cookie '{name}' missing SameSite attribute", "Low", url,
                                          "Cookie may be vulnerable to CSRF.", "cookie_samesite"))
    return findings


def check_cors(url, session):
    findings = []
    try:
        resp = session.get(url, headers={"Origin": "https://evil-test-origin.example"},
                            timeout=TIMEOUT, verify=True)
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")
        if acao == "*" and acac and acac.lower() == "true":
            findings.append(make_finding("Dangerous CORS Configuration", "High", url,
                                          "Access-Control-Allow-Origin: * combined with credentials=true.",
                                          "cors"))
        elif acao == "https://evil-test-origin.example":
            findings.append(make_finding("CORS Reflects Arbitrary Origin", "High", url,
                                          "Server reflects any Origin header back - overly permissive CORS.",
                                          "cors"))
    except requests.RequestException:
        pass
    return findings


def check_ssl(hostname, port=443):
    findings = []
    page = f"https://{hostname}"
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.datetime.utcnow()).days
                    if days_left < 0:
                        findings.append(make_finding("SSL Certificate Expired", "High", page,
                                                      f"Certificate expired {abs(days_left)} days ago.",
                                                      "ssl_expiry"))
                    elif days_left < 30:
                        findings.append(make_finding("SSL Certificate Expiring Soon", "Medium", page,
                                                      f"Certificate expires in {days_left} days.", "ssl_expiry"))

                if protocol in ("TLSv1", "TLSv1.1"):
                    findings.append(make_finding("Outdated TLS Protocol", "High", page,
                                                  f"Server negotiated {protocol}, which is deprecated/insecure.",
                                                  "ssl_protocol"))
    except ssl.SSLCertVerificationError as e:
        findings.append(make_finding("SSL Certificate Verification Failed", "High", page, str(e), "ssl_expiry"))
    except Exception as e:
        findings.append(make_finding("SSL Check Failed", "Info", page, f"Could not verify SSL: {e}", None,
                                      custom_fix="Ensure the site is reachable over HTTPS on port 443."))
    return findings


def check_exposed_files(base_url, session):
    findings = []
    for path in COMMON_SENSITIVE_PATHS:
        test_url = urljoin(base_url, path)
        try:
            resp = session.get(test_url, timeout=TIMEOUT, verify=True, allow_redirects=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                findings.append(make_finding("Exposed Sensitive File/Path", "High", test_url,
                                              f"Publicly accessible: {path} (HTTP {resp.status_code})",
                                              "exposed_file"))
        except requests.RequestException:
            continue
    return findings


def check_outdated_libraries(url, html):
    findings = []
    soup = BeautifulSoup(html, "html.parser")
    scripts = [tag.get("src", "") for tag in soup.find_all("script") if tag.get("src")]
    combined_text = " ".join(scripts)

    for lib, rules in VULNERABLE_LIBS.items():
        match = re.search(rf"{lib}[.\-]?(?:min)?[.\-]?(\d+\.\d+\.\d+)", combined_text, re.IGNORECASE)
        if match:
            version = match.group(1)
            for condition, message in rules:
                threshold = condition.lstrip("<")
                if version_lt(version, threshold):
                    findings.append(make_finding(f"Outdated {lib.capitalize()} ({version})", "High", url,
                                                  message, "outdated_lib"))
                    break
    return findings


def version_lt(v1, v2):
    def parts(v):
        return [int(x) for x in re.findall(r"\d+", v)]
    p1, p2 = parts(v1), parts(v2)
    return p1 < p2


def check_verbose_errors(base_url, session):
    findings = []
    test_url = urljoin(base_url, "this-page-should-not-exist-9999/")
    try:
        resp = session.get(test_url, timeout=TIMEOUT, verify=True)
        text_lower = resp.text.lower()
        signatures = ["stack trace", "traceback (most recent call last)", "fatal error",
                      "warning: mysql", "django.core.exceptions", "microsoft ole db"]
        for sig in signatures:
            if sig in text_lower:
                findings.append(make_finding("Verbose Error Page", "Medium", test_url,
                                              f"Error page leaks internal details (matched: '{sig}').",
                                              "verbose_error"))
                break
    except requests.RequestException:
        pass
    return findings


# ---------------------------------------------------------------------
# Master scan orchestration
# ---------------------------------------------------------------------
def run_scan(url, log_callback):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname
    base_url = f"{parsed.scheme}://{hostname}/"

    session = requests.Session()
    session.headers.update({"User-Agent": "SecurityScannerGUI/1.0 (defensive scan)"})

    all_findings = []

    log_callback(f"Connecting to {url} ...")
    try:
        resp = session.get(url, timeout=TIMEOUT, verify=True)
    except requests.exceptions.SSLError:
        log_callback("SSL verification failed - retrying without verification for header checks only...")
        resp = session.get(url, timeout=TIMEOUT, verify=False)
    except requests.RequestException as e:
        log_callback(f"Could not connect: {e}")
        return []

    log_callback("Checking security headers...")
    all_findings += check_headers(url, resp)

    log_callback("Checking cookies...")
    all_findings += check_cookies(url, resp)

    log_callback("Checking CORS configuration...")
    all_findings += check_cors(url, session)

    if hostname:
        log_callback("Checking SSL/TLS certificate...")
        all_findings += check_ssl(hostname)

    log_callback("Checking for exposed sensitive files...")
    all_findings += check_exposed_files(base_url, session)

    log_callback("Checking for outdated JS libraries...")
    all_findings += check_outdated_libraries(url, resp.text)

    log_callback("Checking for verbose/leaky error pages...")
    all_findings += check_verbose_errors(base_url, session)

    log_callback(f"Scan complete. {len(all_findings)} finding(s).")
    return all_findings


# ---------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
SEVERITY_COLOR = {"High": "#ffd6d6", "Medium": "#fff3cd", "Low": "#d6e9ff", "Info": "#eeeeee"}


class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Website Security Scanner")
        self.root.geometry("1150x700")
        self.findings = []

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=12, pady=10)

        ttk.Label(top, text="Website URL:", font=("Segoe UI", 10, "bold")).pack(side="left")
        self.url_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.url_var, width=50)
        entry.pack(side="left", padx=8)
        entry.bind("<Return>", lambda e: self.start_scan())

        self.scan_btn = ttk.Button(top, text="🔍 Scan", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=5)

        self.export_btn = ttk.Button(top, text="⬇️ Export CSV", command=self.export_csv, state="disabled")
        self.export_btn.pack(side="left", padx=5)

        disclaimer = ttk.Label(
            self.root,
            text="⚠️ Only scan websites you own or have explicit permission to test. "
                 "Automated results may include false positives/negatives - verify manually.",
            foreground="#b30000", font=("Segoe UI", 9, "italic")
        )
        disclaimer.pack(fill="x", padx=12, pady=(0, 5))

        # Log area
        log_frame = ttk.LabelFrame(self.root, text="Scan Progress")
        log_frame.pack(fill="x", padx=12, pady=5)
        self.log_text = tk.Text(log_frame, height=5, font=("Consolas", 9))
        self.log_text.pack(fill="x", padx=5, pady=5)

        # Results table
        results_frame = ttk.LabelFrame(self.root, text="Findings")
        results_frame.pack(fill="both", expand=True, padx=12, pady=10)

        columns = ("severity", "check", "page", "detail", "fix")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("check", text="Issue")
        self.tree.heading("page", text="Page / Location")
        self.tree.heading("detail", text="Detail")
        self.tree.heading("fix", text="How to Fix")

        self.tree.column("severity", width=70, anchor="center")
        self.tree.column("check", width=180)
        self.tree.column("page", width=220)
        self.tree.column("detail", width=280)
        self.tree.column("fix", width=320)

        self.tree.pack(fill="both", expand=True, side="left")
        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=vsb.set)

        for sev, color in SEVERITY_COLOR.items():
            self.tree.tag_configure(sev, background=color)

        self.summary_label = ttk.Label(self.root, text="", font=("Segoe UI", 10, "bold"))
        self.summary_label.pack(fill="x", padx=12, pady=(0, 10))

    def log(self, msg):
        def _append():
            self.log_text.insert("end", msg + "\n")
            self.log_text.see("end")
        self.root.after(0, _append)

    def start_scan(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Missing URL", "Please enter a website URL.")
            return

        confirm = messagebox.askyesno(
            "Confirm Authorization",
            f"Do you own '{url}' or have explicit permission to scan it?\n\n"
            "Only proceed if the answer is yes."
        )
        if not confirm:
            return

        self.scan_btn.config(state="disabled")
        self.export_btn.config(state="disabled")
        self.log_text.delete("1.0", "end")
        self.tree.delete(*self.tree.get_children())
        self.summary_label.config(text="Scanning...")

        threading.Thread(target=self._do_scan, args=(url,), daemon=True).start()

    def _do_scan(self, url):
        try:
            findings = run_scan(url, self.log)
            findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
            self.findings = findings
            self.root.after(0, lambda: self.show_results(findings))
        except Exception as e:
            self.log(f"ERROR: {e}")
            self.root.after(0, lambda: messagebox.showerror("Scan failed", str(e)))
        finally:
            self.root.after(0, lambda: self.scan_btn.config(state="normal"))

    def show_results(self, findings):
        for f in findings:
            self.tree.insert("", "end", values=(f["severity"], f["check"], f["page"], f["detail"], f["fix"]),
                              tags=(f["severity"],))

        high = sum(1 for f in findings if f["severity"] == "High")
        med = sum(1 for f in findings if f["severity"] == "Medium")
        low = sum(1 for f in findings if f["severity"] == "Low")
        self.summary_label.config(
            text=f"Total findings: {len(findings)}   |   🔴 High: {high}   🟡 Medium: {med}   🔵 Low: {low}"
        )
        if findings:
            self.export_btn.config(state="normal")

    def export_csv(self):
        if not self.findings:
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="security_scan_report.csv",
                                             filetypes=[("CSV files", "*.csv")])
        if not path:
            return
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["severity", "check", "page", "detail", "fix"])
            writer.writeheader()
            writer.writerows(self.findings)
        messagebox.showinfo("Exported", f"Report saved to:\n{path}")


def main():
    root = tk.Tk()
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    app = ScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
