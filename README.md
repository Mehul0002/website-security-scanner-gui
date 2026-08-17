# 🛡️ Website Security Scanner — Desktop GUI

Enter a website URL, click Scan, and get a report of common security
misconfigurations — exact issue, page/location, severity, and how to
fix it. Built with Python + Tkinter. Free, open source, runs locally.

![Dashboard preview](screenshots/dashboard_preview.png)
*Example scan results — findings sorted by severity, with the exact
page and a fix suggestion for each issue.*

## ⚠️ Legal & accuracy notice — please read
- **Only scan websites you own or have explicit written permission to
  test.** Scanning systems without authorization is illegal in most
  countries (e.g. under Computer Misuse Act type laws), regardless of
  good intent. This app shows a confirmation prompt every scan to
  remind you of this.
- This is an **automated, passive scanner**. No automated tool — free
  or paid — can guarantee 100% accuracy. It can produce **false
  positives/negatives** and **cannot** detect business-logic
  vulnerabilities (e.g. broken payment logic, access-control flaws
  that require human judgment). Treat results as a helpful first pass,
  not a substitute for a professional penetration test.
- Checks are passive/non-destructive — the tool does not attempt to
  exploit anything, only detects misconfigurations and known patterns.

## ✨ What it checks
| Category | Details |
|---|---|
| Security headers | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| SSL/TLS | Certificate expiry, outdated TLS version, verification errors |
| Exposed files | `.env`, `.git/config`, backup files, `wp-config.php.bak`, exposed admin paths, etc. |
| Cookies | Missing `Secure`, `HttpOnly`, `SameSite` flags |
| CORS | Overly permissive `Access-Control-Allow-Origin` + credentials |
| Outdated libraries | Known-vulnerable versions of jQuery, Bootstrap, AngularJS, Lodash |
| Information disclosure | Server/X-Powered-By banners, verbose error pages leaking stack traces |

Each finding shows: **Severity (High/Medium/Low)**, the **exact
page/URL**, a **detail** of what was found, and a concrete **how to
fix** suggestion.

## What you need (as a user)
- Python 3.8+
- Internet connection (to actually reach the site you're scanning)
- No paid API, no signup required

## Setup (VS Code)

```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
python security_scanner_gui.py
```

A window opens — no browser needed.

## How to use
1. Enter the full URL (e.g. `https://yourdomain.com`) in the box.
2. Click **Scan**.
3. Confirm you own/have permission for the site (required every scan).
4. Watch the progress log as it checks each category.
5. Review findings in the table — sorted by severity (High → Low).
6. Click **Export CSV** to save the report for later or to share
   with a developer/team.

## 📦 Don't want to install Python? Use the standalone app

If you just want to **run the tool** without setting up Python, check
this repo's **[Releases](../../releases)** page — a ready-to-run
`.exe` (Windows) may be available there. Just download and double-click.

## 🔨 Building your own standalone .exe (for maintainers)

Want to publish a version people can run without installing Python?
This repo includes a build script using [PyInstaller](https://pyinstaller.org/):

```bash
pip install -r requirements.txt
python build_exe.py
```

This creates a single executable file in the `dist/` folder:
- Windows → `dist/security_scanner_gui.exe`
- Mac/Linux → `dist/security_scanner_gui`

Upload that file to your repo's **GitHub Releases** section (Releases →
Draft a new release → attach the file). Anyone can then download and
run it directly — no Python, no `pip install`, nothing.

> Note: Build the `.exe` on Windows to get a Windows executable, and
> on Mac/Linux to get a Mac/Linux binary — PyInstaller doesn't
> cross-compile. If you want a Windows `.exe` automatically built on
> every release, set up a free **GitHub Actions** workflow that runs
> `build_exe.py` on a `windows-latest` runner and uploads the result.

## Roadmap ideas (optional extensions)
- Multi-page crawling (currently checks the entered URL + common paths)
- PDF report export
- Integration with a live CVE database for more accurate library checks
- Authenticated scanning (login first, then scan protected pages)

## Disclaimer
Educational / defensive security tool. Use only on systems you're
authorized to test. Not a replacement for professional penetration
testing or a bug bounty program.

## License
MIT — free to use, modify, and share.
