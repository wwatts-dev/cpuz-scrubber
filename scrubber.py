from pathlib import Path
import re
import sys


def scrub_cpuz(input_path: Path, output_path: Path) -> None:
    content = input_path.read_text(encoding="utf-8", errors="ignore")

    patterns = [
        (r"(User Name\s*:\s*).*", r"\1[SCRUBBED_USER]"),
        (r"(Computer Name\s*:\s*).*", r"\1[SCRUBBED_HOST]"),
        (r"(Serial Number\s*:\s*).*", r"\1[SCRUBBED_SERIAL]"),
        (r"(Serial number\s*:\s*).*", r"\1[SCRUBBED_SERIAL]"),
        (r"(UUID\s*:\s*).*", r"\1[SCRUBBED_UUID]"),
    ]

    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)

    output_path.write_text(content, encoding="utf-8")


def resolve_input_file() -> Path:
    if len(sys.argv) > 1:
        return Path(sys.argv[1])

    # Fallback: Standard library GUI file picker
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        path = filedialog.askopenfilename(
            title="Select CPU-Z Log", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if path:
            return Path(path)
    except Exception:
        pass

    sys.exit("Error: No input file provided.")


if __name__ == "__main__":
    infile = resolve_input_file()
    outfile = infile.with_name(f"sanitized_{infile.name}")
    scrub_cpuz(infile, outfile)
    print(f"Output saved to: {outfile}")