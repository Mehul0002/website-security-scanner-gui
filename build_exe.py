"""
Build script - creates a standalone executable (.exe on Windows,
binary on Mac/Linux) so users can run the scanner WITHOUT installing
Python or any dependencies.

Usage:
    python build_exe.py

Output:
    dist/security_scanner_gui.exe   (Windows)
    dist/security_scanner_gui       (Mac/Linux)

You can then attach this file to a GitHub Release so anyone can
download and double-click to run - no setup needed.
"""

import subprocess
import sys


def main():
    print("Installing PyInstaller (if not already installed)...")
    subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller", "--break-system-packages"],
                    check=False)
    subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=False)

    print("\nBuilding standalone executable...")
    subprocess.run([
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name", "security_scanner_gui",
        "security_scanner_gui.py"
    ], check=True)

    print("\n✅ Build complete!")
    print("Find your executable in the 'dist' folder.")
    print("Upload that file to a GitHub Release so others can run it")
    print("without installing Python.")


if __name__ == "__main__":
    main()
