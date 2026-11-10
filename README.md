# CPU-Z Report Scrubber

CPU-Z ([official CPU-Z page](https://www.cpuid.com/softwares/cpu-z.html)) reports are shared when someone asks for help with a PC (or wants to effortlessly share their hardware specs with another PC user). A report also contains serial numbers, a system UUID, monitor and disk serials, and sometimes a device path that identifies that one computer. This program writes a copy with those values removed so the hardware details can be posted without handing out those identifiers.

The original file is left untouched. Share the sanitized copy. Keep the scrub log on your machine: it lists every original value that was removed by this program.

Each removed value is replaced with a token such as `[SCRUBBED_SERIAL]` or `[SCRUBBED_UUID]`.

## Running Without the Command Line (For End Users)

If you have the standalone executable (`scrubber.exe` on Windows):

1. **Double-click** the program.
2. A file selection window opens.
3. Select your CPU-Z report (`.txt`, `.htm`, or `.html`).
4. A message shows how many values were removed.
5. In the same folder as the report you get:
   - `sanitized_<original_name>` — the copy you can share
   - `scrublog_<original_stem>.txt` — every removed value

Closing the file window without choosing a file writes nothing. Running the program again replaces the previous sanitized copy and scrub log.

**NOTE**: If the report file name is the computer name, rename the sanitized copy before you post it. The program does not rename files.

---

## Running from Source (Python Required)

Uses Python 3.8+ and the standard library only. Use `python`, or `python3` where that is the installed command.

```bash
python scrubber.py
python scrubber.py report.txt
```

With no file path, a file window opens. On Linux that window needs Tk (`python3-tk` on Debian and Ubuntu). Passing a path skips the window.

## What is removed

Removed when the report contains them: system, board, chassis, memory, disk, monitor, and USB serials; PCI EUI-64 values, including the same bytes in a PCI register dump; drive instance ids inside a device path; service tags and Dell OEM blocks such as `7[ABC1234]`; UUID / GUID; asset tags; user and computer names; `C:\Users\<name>` paths; MAC addresses; email addresses; Windows account SIDs; Windows product id and product key.

Left in place: CPU, motherboard, RAM part numbers, firmware, BIOS version, OS version, SMBIOS placeholders (`To be filled by O.E.M.`, all-zero serials), and Windows storage device ids that are the same on every machine.

A CPU-Z text report has no Windows user or computer name unless those labels were pasted in. Custom text in DMI product, model, or family is also left in place. Read those lines before you publish. A CPU-Z HTML save is often shorter than the text save and may omit disk serials and PCI dumps entirely.

---

## Building a Standalone Executable (For Developers)

The executable is built for the operating system you run PyInstaller on. Windows produces `dist/scrubber.exe`. Linux and macOS produce `dist/scrubber`.

```bash
pip install pyinstaller
python -m PyInstaller --onefile --noconsole scrubber.py
python -m unittest test_scrubber.py
```

Text reports separate the label and the value with tabs, and Windows often saves them as UTF-16. Colon labels such as `User Name:` are recognized too.

---

## Reporting a Bad Scrub

GitHub issues are public. Do not attach the scrub log, the original report, or real serials, UUIDs, or names. Paste the sanitized line, or the error text.

[Open a bug report](https://github.com/wwatts-dev/cpuz-scrubber/issues/new?template=bug_report.yml)

---

## License

Distributed under the MIT license. See `LICENSE` for details.
