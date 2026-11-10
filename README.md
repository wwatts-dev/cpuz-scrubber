# CPU-Z Report Scrubber

A lightweight utility to sanitize sensitive system identification strings (usernames, hostnames, hardware serial numbers, UUIDs) from CPU-Z text reports.

## Running Without the Command Line (For End Users)

If you have the standalone executable (`scrubber.exe`):

1. **Double-click** `scrubber.exe`.
2. A file selection window will automatically open.
3. Select your raw CPU-Z text report.
4. A sanitized copy (`sanitized_<original_name>.txt`) is automatically saved in the same folder.

---

## Running from Source (Python Required)

If running the Python script directly, ensure Python 3+ is installed:

```bash
python scrubber.py
```

---

## Building a Standalone Executable (For Developers)

To generate a zero-dependency executable for end-users:

```bash
pip install pyinstaller
python -m PyInstaller --onefile --noconsole scrubber.py
```

The compiled binary will be located in the `dist/` directory.

---

## License

Distributed under the MIT license. See `LICENSE` for details.