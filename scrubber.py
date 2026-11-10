"""Sanitize identifying values in a CPU-Z text or HTML report.

CPU-Z text reports separate labels and values with tabs, not colons, and
Windows often saves them as UTF-16. Colon labels such as "User Name:" still
work. Part numbers, firmware, model names, and BIOS/OS versions are kept.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


class NotAReportError(ValueError):
    """Input does not look like text or HTML."""


@dataclass(frozen=True)
class Change:
    line: int
    section: str
    field: str
    kind: str
    original: str
    replacement: str


@dataclass(frozen=True)
class Skip:
    line: int
    section: str
    field: str
    value: str


_TOKEN = {
    "USER": "[SCRUBBED_USER]",
    "HOST": "[SCRUBBED_HOST]",
    "SERIAL": "[SCRUBBED_SERIAL]",
    "UUID": "[SCRUBBED_UUID]",
    "ASSET": "[SCRUBBED_ASSET]",
    "MAC": "[SCRUBBED_MAC]",
    "EMAIL": "[SCRUBBED_EMAIL]",
    "SID": "[SCRUBBED_SID]",
    "ORG": "[SCRUBBED_ORG]",
}

# Exact labels after whitespace is collapsed. "serial" and "uuid" variants
# that are not listed here are still caught by kind_for_label().
_LABEL_KIND = {
    "user name": "USER",
    "username": "USER",
    "registered owner": "USER",
    "registeredowner": "USER",
    "computer name": "HOST",
    "computername": "HOST",
    "host name": "HOST",
    "hostname": "HOST",
    "machine name": "HOST",
    "pc name": "HOST",
    "netbios name": "HOST",
    "domain name": "HOST",
    "workgroup": "HOST",
    "registered organization": "ORG",
    "registeredorganization": "ORG",
    "uuid": "UUID",
    "guid": "UUID",
    "system uuid": "UUID",
    "machine guid": "UUID",
    "serial": "SERIAL",
    "serial number": "SERIAL",
    "serial no": "SERIAL",
    "s/n": "SERIAL",
    "sn": "SERIAL",
    "iserial": "SERIAL",
    "service tag": "SERIAL",
    "ppid": "SERIAL",
    "eppid": "SERIAL",
    "product key": "SERIAL",
    "product id": "SERIAL",
    "cd key": "SERIAL",
    "license key": "SERIAL",
    "windows key": "SERIAL",
    "asset tag": "ASSET",
    "mac": "MAC",
    "mac address": "MAC",
    "physical address": "MAC",
    "hardware address": "MAC",
}

_PLACEHOLDERS = {
    "none",
    "n/a",
    "na",
    "not specified",
    "not available",
    "not present",
    "not applicable",
    "not defined",
    "unknown",
    "undefined",
    "invalid",
    "empty",
    "to be filled by o.e.m.",
    "to be filled by o.e.m",
    "to be filled by oem",
    "o.e.m.",
    "oem",
    "system serial number",
    "chassis serial number",
    "base board serial number",
    "baseboard serial number",
    "serial number",
    "default string",
    "default",
    "default tag",
    "no asset tag",
    "no asset information",
    "asset-1234567890",
    "no serial",
    "noserial",
    "system manufacturer",
    "system product name",
    "system version",
    "sku",
    "workgroup",
    "mshome",
    "type1productconfigid",
}

_SAFE_USER_DIRS = {
    "public",
    "default",
    "default user",
    "all users",
    "defaultaccount",
    "defaultapppool",
    "wdagutilityaccount",
}

_FIELD_RE = re.compile(
    r"^(?P<indent>[ \t]*)"
    r"(?P<label>[^\t:=]+?)"
    r"(?P<sep>[ \t]*:[ \t]*|\t[ \t]*|[ ]{2,}| = )"
    r"(?P<value>.*)$"
)
_CONTEXT_RE = re.compile(
    r"(?:drive|dimm #|dimm|display|display adapter|usb device|socket)\Z",
    re.IGNORECASE,
)
_OEM_RE = re.compile(r"(?:oem )?string(?: \d+)?\Z", re.IGNORECASE)
_TR_RE = re.compile(r"<tr\b[^>]*>.*?</tr>", re.IGNORECASE | re.DOTALL)
_TD_RE = re.compile(r"<td\b[^>]*>(.*?)</td>", re.IGNORECASE | re.DOTALL)
_TD_PAIR_RE = re.compile(
    r"(<td\b[^>]*>)(.*?)(</td>)(\s*<td\b[^>]*>)(.*?)(</td>)",
    re.IGNORECASE | re.DOTALL,
)
_UUID_RE = re.compile(
    r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}|"
    r"\b[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\b"
)
# Windows storage device interface ids. These are the same on every machine.
_PUBLIC_UUIDS = {
    "53f56307-b6bf-11d0-94f2-00a0c91efb8b",  # disk
    "53f56308-b6bf-11d0-94f2-00a0c91efb8b",  # cd-rom
    "53f5630a-b6bf-11d0-94f2-00a0c91efb8b",  # partition
    "53f5630b-b6bf-11d0-94f2-00a0c91efb8b",  # tape
    "53f5630c-b6bf-11d0-94f2-00a0c91efb8b",  # write-once disk
    "53f5630d-b6bf-11d0-94f2-00a0c91efb8b",  # volume
    "53f56310-b6bf-11d0-94f2-00a0c91efb8b",  # medium changer
    "53f56311-b6bf-11d0-94f2-00a0c91efb8b",  # floppy
    "53f56312-b6bf-11d0-94f2-00a0c91efb8b",  # cd changer
    "2accfe60-c130-11d2-b082-00a0c91efb8b",  # storage port
    "7f108a28-9833-4b3b-b780-2c6b5fa5c062",  # hidden volume
}
_DEVICE_INSTANCE_RE = re.compile(r"#\d+&[0-9A-Fa-f]{4,}&\d+&[0-9A-Fa-f]{4,}")
_EUI64_RE = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}\Z")
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_SID_RE = re.compile(r"\bS-1-5-\d+(?:-\d+){3,}\b", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PATH_RE = re.compile(
    r"(?i)([A-Za-z]:[/\\](?:Users|Documents and Settings)[/\\])"
    r"([^/\\:*?\"<>|\r\n]+)"
)
_DELL_RE = re.compile(r"\d\[([A-Z0-9]{4,})\]", re.IGNORECASE)
_TOKEN_RE = re.compile(r"\[SCRUBBED_[A-Z]+\]\Z")


def decode_bytes(raw: bytes) -> tuple[str, str]:
    """Return report text and the encoding name that produced it."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text, encoding = raw.decode("utf-16"), "utf-16"
    elif raw.startswith(b"\xef\xbb\xbf"):
        text, encoding = raw.decode("utf-8-sig"), "utf-8"
    elif _is_utf16_le(raw):
        try:
            text, encoding = raw.decode("utf-16-le"), "utf-16-le"
        except UnicodeDecodeError:
            text, encoding = _decode_utf8_or_cp1252(raw)
    else:
        text, encoding = _decode_utf8_or_cp1252(raw)
    return text.lstrip("\ufeff").replace("\u00a0", " "), encoding


def looks_like_text(text: str) -> bool:
    if not text.strip() or "\x00" in text:
        return False
    sample = text[:8000]
    bad = sum(1 for char in sample if ord(char) < 32 and char not in "\n\r\t\f")
    return bad * 50 <= len(sample)


def scrub_text(text: str) -> tuple[str, list[Change], list[Skip]]:
    """Return cleaned text, replacements, and sensitive fields left as placeholders."""
    text = text.replace("\u00a0", " ")
    newline = "\r\n" if "\r\n" in text else "\n"
    body = text.replace("\r\n", "\n").replace("\r", "\n")
    ends_with_newline = body.endswith("\n")
    lines = body.split("\n")
    if ends_with_newline:
        lines.pop()
    return _scrub_lines(lines, ends_with_newline, newline)


def output_paths(infile: Path) -> tuple[Path, Path]:
    """Sanitized report and scrub log, both in the same folder as the input."""
    return (
        infile.with_name(f"sanitized_{infile.name}"),
        infile.with_name(f"scrublog_{infile.stem}.txt"),
    )


def scrub_file(input_path: Path, output_path: Path, log_path: Path) -> tuple[list[Change], list[Skip]]:
    text, encoding = decode_bytes(input_path.read_bytes())
    if not looks_like_text(text):
        raise NotAReportError(
            "File does not look like a CPU-Z text or HTML report. Nothing was written."
        )
    cleaned, changes, skips = scrub_text(text)
    log = render_log(input_path, output_path, encoding, changes, skips)
    output_path.write_bytes(cleaned.encode("utf-8"))
    log_path.write_bytes(log.encode("utf-8"))
    return changes, skips


def render_log(
    source: Path,
    output: Path,
    encoding: str,
    changes: list[Change],
    skips: list[Skip],
) -> str:
    counts: dict[str, int] = {}
    for change in changes:
        counts[change.kind] = counts.get(change.kind, 0) + 1

    lines = [
        "CPU-Z scrub log",
        f"Source file: {source.name}",
        f"Sanitized file: {output.name}",
        f"Read as: {encoding}",
        "",
        f"Removed: {len(changes)}",
        f"Already generic: {len(skips)}",
        "",
    ]
    if counts:
        lines.append("Removed by type:")
        for kind in sorted(counts):
            lines.append(f"  {kind}  {counts[kind]}")
        lines.append("")
    if changes:
        lines.append(
            "This log repeats the private values that were removed. "
            "Share the sanitized report, not this log."
        )
    else:
        lines.append(
            "Nothing identifying was removed. Read the sanitized report once before you share it."
        )
    lines.append("")

    if changes:
        lines.append("Removed values:")
        for number, change in enumerate(changes, start=1):
            where = change.section or "-"
            lines.append(
                f"[{number}] line {change.line} | {where} | {change.field} | {change.kind}"
            )
            lines.append(f"    original: {_one_line(change.original)}")
            lines.append(f"    replacement: {change.replacement}")
        lines.append("")

    if skips:
        lines.append("Already generic (left unchanged):")
        for skip in skips:
            where = skip.section or "-"
            shown = skip.value if skip.value else "(empty)"
            lines.append(f"  line {skip.line} | {where} | {skip.field} | {_one_line(shown)}")
        lines.append("")

    lines.extend(
        [
            "CPU, motherboard, RAM part numbers, firmware, BIOS version, and OS version stay in the report.",
            "A stock CPU-Z report has no Windows user or computer name. Those are removed when a label or a user-folder path is present.",
            "SMBIOS placeholders such as \"To be filled by O.E.M.\" and all-zero serials stay as they are.",
            "Custom names typed into DMI product, model, or family are not removed. Read those lines before you publish.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        infile = _resolve_input_file(args)
        if not infile.is_file():
            raise SystemExit(f"Error: file not found: {infile}")
        outfile, logfile = output_paths(infile)
        if _same_file(outfile, infile) or _same_file(logfile, infile):
            raise SystemExit("Error: refusing to overwrite the input file.")
        changes, skips = scrub_file(infile, outfile, logfile)
    except NotAReportError as exc:
        _fail(str(exc))
    except OSError as exc:
        _fail(f"Error: {exc}")
    except SystemExit as exc:
        if isinstance(exc.code, str):
            _fail(exc.code)
        raise
    _announce(_summary(outfile, logfile, changes, skips))
    return 0


def _scrub_lines(
    lines: list[str], ends_with_newline: bool, newline: str
) -> tuple[str, list[Change], list[Skip]]:
    changes: list[Change] = []
    skips: list[Skip] = []
    section = ""
    output: list[str] = []
    sections: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if re.search(r"<tr\b", line, re.IGNORECASE) and not re.search(
            r"</tr>", line, re.IGNORECASE
        ):
            start = index
            block = [line]
            index += 1
            while index < len(lines):
                block.append(lines[index])
                closed = bool(re.search(r"</tr>", lines[index], re.IGNORECASE))
                index += 1
                if closed:
                    break
            section, parts = _scrub_html_block(block, section, start + 1, changes, skips)
            output.extend(parts)
            sections.extend([section] * len(parts))
            continue
        new_line, section = _scrub_one(line, section, index + 1, changes, skips)
        output.append(new_line)
        sections.append(section)
        index += 1

    output = _redact_eui_dumps(output, sections, changes)
    cleaned = "\n".join(output)
    if ends_with_newline:
        cleaned += "\n"
    if newline == "\r\n":
        cleaned = cleaned.replace("\n", "\r\n")
    return cleaned, changes, skips


def _scrub_html_block(
    block: list[str],
    section: str,
    start_line: int,
    changes: list[Change],
    skips: list[Skip],
) -> tuple[str, list[str]]:
    joined, section = _process_html("\n".join(block), section, start_line, changes, skips)
    parts = []
    for offset, part in enumerate(joined.split("\n")):
        parts.append(_apply_inline(part, section, start_line + offset, changes))
    return section, parts


def _scrub_one(
    line: str,
    section: str,
    line_no: int,
    changes: list[Change],
    skips: list[Skip],
) -> tuple[str, str]:
    if re.search(r"<t[dr]\b", line, re.IGNORECASE):
        line, section = _process_html(line, section, line_no, changes, skips)
    else:
        line, section = _process_field(line, section, line_no, changes, skips)
    return _apply_inline(line, section, line_no, changes), section


def _process_field(
    line: str,
    section: str,
    line_no: int,
    changes: list[Change],
    skips: list[Skip],
) -> tuple[str, str]:
    match = _FIELD_RE.match(line)
    if not match:
        if _looks_like_header(line):
            section = line.strip()
        return line, section

    label = match.group("label").strip()
    value = match.group("value").strip()
    if _CONTEXT_RE.fullmatch(_norm_label(label)) and re.fullmatch(r"\d+", value):
        return line, f"{label} {value}".strip()

    token = _consider_value(label, value, section, line_no, changes, skips)
    if token is None:
        if not value and not match.group("indent") and _looks_like_header(label):
            section = label
        return line, section
    return line[: match.start("value")] + token + line[match.end("value") :], section


def _process_html(
    fragment: str,
    section: str,
    line_no: int,
    changes: list[Change],
    skips: list[Skip],
) -> tuple[str, str]:
    if re.search(r"<tr\b", fragment, re.IGNORECASE):
        return _replace_rows(fragment, section, line_no, changes, skips)
    return _replace_pairs(fragment, section, line_no, changes, skips), section


def _replace_rows(
    fragment: str,
    section: str,
    line_no: int,
    changes: list[Change],
    skips: list[Skip],
) -> tuple[str, str]:
    def repl(match: re.Match[str]) -> str:
        nonlocal section
        row = match.group(0)
        cells = list(_TD_RE.finditer(row))
        if len(cells) < 2:
            title = _strip_tags(cells[0].group(1)) if cells else ""
            if _looks_like_header(title):
                section = title
            return row
        edits: list[tuple[int, int, str]] = []
        for index in range(0, len(cells) - 1, 2):
            label = _strip_tags(cells[index].group(1))
            value = _strip_tags(cells[index + 1].group(1))
            token = _consider_value(label, value, section, line_no, changes, skips)
            if token is None:
                continue
            value_cell = cells[index + 1]
            edits.append((value_cell.start(1), value_cell.end(1), token))
        for start, end, token in reversed(edits):
            row = row[:start] + token + row[end:]
        return row

    return _TR_RE.sub(repl, fragment), section


def _replace_pairs(
    fragment: str,
    section: str,
    line_no: int,
    changes: list[Change],
    skips: list[Skip],
) -> str:
    def repl(match: re.Match[str]) -> str:
        label = _strip_tags(match.group(2))
        value = _strip_tags(match.group(5))
        token = _consider_value(label, value, section, line_no, changes, skips)
        if token is None:
            return match.group(0)
        return (
            match.group(1)
            + match.group(2)
            + match.group(3)
            + match.group(4)
            + token
            + match.group(6)
        )

    return _TD_PAIR_RE.sub(repl, fragment)


def _consider_value(
    label: str,
    value: str,
    section: str,
    line_no: int,
    changes: list[Change],
    skips: list[Skip],
) -> str | None:
    kind = _resolve_kind(label, value)
    if not kind:
        return None
    if _is_token(value) or _is_public_uuid(value):
        return None
    if _is_placeholder(value):
        skips.append(Skip(line_no, section, _norm_label(label) or label.strip(), value or "(empty)"))
        return None
    token = _TOKEN[kind]
    changes.append(
        Change(line_no, section, _norm_label(label) or label.strip(), kind, value, token)
    )
    return token


def _apply_inline(line: str, section: str, line_no: int, changes: list[Change]) -> str:
    line = _sub_simple(line, _UUID_RE, "UUID", "uuid", section, line_no, changes)
    line = _sub_simple(line, _MAC_RE, "MAC", "mac", section, line_no, changes)
    line = _sub_simple(line, _SID_RE, "SID", "sid", section, line_no, changes)
    line = _sub_simple(line, _EMAIL_RE, "EMAIL", "email", section, line_no, changes)
    line = _sub_path(line, section, line_no, changes)
    line = _sub_device_instance(line, section, line_no, changes)
    line = _sub_dell(line, section, line_no, changes)
    return line


def _sub_simple(
    line: str,
    pattern: re.Pattern[str],
    kind: str,
    field: str,
    section: str,
    line_no: int,
    changes: list[Change],
) -> str:
    def repl(match: re.Match[str]) -> str:
        original = match.group(0)
        if _is_placeholder(original) or _is_token(original) or _is_public_uuid(original):
            return original
        token = _TOKEN[kind]
        changes.append(Change(line_no, section, field, kind, original, token))
        return token

    return pattern.sub(repl, line)


def _sub_path(line: str, section: str, line_no: int, changes: list[Change]) -> str:
    def repl(match: re.Match[str]) -> str:
        user = match.group(2).strip()
        if user.casefold() in _SAFE_USER_DIRS or _is_placeholder(user) or _is_token(user):
            return match.group(0)
        original = match.group(1) + user
        replacement = match.group(1) + _TOKEN["USER"]
        changes.append(Change(line_no, section, "user path", "USER", original, replacement))
        return replacement

    return _PATH_RE.sub(repl, line)


def _sub_device_instance(line: str, section: str, line_no: int, changes: list[Change]) -> str:
    def repl(match: re.Match[str]) -> str:
        original = match.group(0)
        replacement = "#" + _TOKEN["SERIAL"]
        changes.append(Change(line_no, section, "device instance", "SERIAL", original, replacement))
        return replacement

    return _DEVICE_INSTANCE_RE.sub(repl, line)


def _sub_dell(line: str, section: str, line_no: int, changes: list[Change]) -> str:
    def repl(match: re.Match[str]) -> str:
        if _is_placeholder(match.group(1)):
            return match.group(0)
        original = match.group(0)
        token = _TOKEN["SERIAL"]
        changes.append(Change(line_no, section, "dell oem id", "SERIAL", original, token))
        return token

    return _DELL_RE.sub(repl, line)


def _resolve_kind(label: str, value: str) -> str | None:
    kind = _kind_for_label(label)
    if kind:
        return kind
    if _OEM_RE.fullmatch(_norm_label(label)) and _oem_is_sensitive(value):
        return "SERIAL"
    return None


def _kind_for_label(label: str) -> str | None:
    norm = _norm_label(label)
    mapped = _LABEL_KIND.get(norm)
    if mapped:
        return mapped
    if "asset tag" in norm:
        return "ASSET"
    if re.search(r"\bserial\b", norm) or norm in {"s/n", "sn", "serial#", "iserial"}:
        return "SERIAL"
    compact = norm.replace(" ", "")
    if compact in {"serialnumber", "serialno", "iserial"}:
        return "SERIAL"
    if re.search(r"\b(?:uuid|guid)\b", norm) or norm.endswith(("uuid", "guid")):
        return "UUID"
    return None


def _oem_is_sensitive(value: str) -> bool:
    blobs = _DELL_RE.findall(value)
    if any(not _is_placeholder(blob) for blob in blobs):
        return True
    return _looks_like_unique_token(value)


def _looks_like_unique_token(value: str) -> bool:
    token = value.strip()
    return bool(
        re.fullmatch(r"[A-Z0-9]{6,24}", token, re.IGNORECASE)
        and re.search(r"\d", token)
        and re.search(r"[A-Z]", token, re.IGNORECASE)
    )


def _norm_label(label: str) -> str:
    label = label.strip().lower().replace("\uff1a", ":")
    label = re.sub(r"\s+", " ", label).strip(" :.")
    label = re.sub(r"\s*\([^)]*\)\s*$", "", label).strip()
    return label


def _looks_like_header(line: str) -> bool:
    if not line or line[0] in " \t":
        return False
    stripped = line.strip()
    if not stripped or len(stripped) > 80:
        return False
    if re.fullmatch(r"[-=*_]{3,}", stripped):
        return False
    if re.search(r"[@:\\/\[\]<>]", stripped):
        return False
    if _secret_shape(stripped):
        return False
    return True


def _secret_shape(value: str) -> bool:
    return any(
        pattern.search(value)
        for pattern in (_UUID_RE, _MAC_RE, _SID_RE, _EMAIL_RE, _PATH_RE, _DELL_RE)
    )


def _is_placeholder(value: str) -> bool:
    text = value.strip().strip("{}").strip()
    if not text:
        return True
    lowered = re.sub(r"\s+", " ", text.casefold())
    if lowered in _PLACEHOLDERS:
        return True
    compact = re.sub(r"[\s\-{}:.]", "", lowered)
    if not compact:
        return True
    if set(compact) <= {"0"}:
        return True
    if len(compact) >= 8 and set(compact) <= {"f"}:
        return True
    if len(compact) >= 4 and set(compact) <= {"x"}:
        return True
    return False


def _is_public_uuid(value: str) -> bool:
    body = value.strip().strip("{}").casefold()
    return body in _PUBLIC_UUIDS


def _eui_dump_text(value: str) -> str | None:
    """PCI dumps store an EUI-64 as the little-endian bytes of the printed value."""
    text = value.strip()
    if not _EUI64_RE.fullmatch(text):
        return None
    raw = bytes.fromhex(text.replace("-", ""))
    return " ".join(f"{byte:02X}" for byte in reversed(raw))


def _redact_eui_dumps(
    lines: list[str], sections: list[str], changes: list[Change]
) -> list[str]:
    compiled: list[re.Pattern[str]] = []
    seen: set[str] = set()
    for change in list(changes):
        form = _eui_dump_text(change.original)
        if form is None or form.casefold() in seen:
            continue
        seen.add(form.casefold())
        compiled.append(re.compile(r"(?i)" + r"\s+".join(re.escape(part) for part in form.split())))
    if not compiled:
        return lines
    output: list[str] = []
    for index, line in enumerate(lines):
        section = sections[index] if index < len(sections) else ""
        for pattern in compiled:
            line = _replace_eui_run(line, pattern, section, index + 1, changes)
        output.append(line)
    return output


def _replace_eui_run(
    line: str,
    pattern: re.Pattern[str],
    section: str,
    line_no: int,
    changes: list[Change],
) -> str:
    def repl(match: re.Match[str]) -> str:
        changes.append(
            Change(line_no, section, "eui bytes", "SERIAL", match.group(0), _TOKEN["SERIAL"])
        )
        return _TOKEN["SERIAL"]

    return pattern.sub(repl, line)


def _is_token(value: str) -> bool:
    return bool(_TOKEN_RE.fullmatch(value.strip()))


def _strip_tags(value: str) -> str:
    value = (
        value.replace("&nbsp;", " ")
        .replace("&#160;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
    )
    value = re.sub(r"(?is)<[^>]+>", "", value)
    return re.sub(r"\s+", " ", value).strip()


def _one_line(value: str) -> str:
    value = value.replace("\r", " ").replace("\n", " ")
    if len(value) <= 2000:
        return value
    return value[:2000] + "...(truncated)"


def _decode_utf8_or_cp1252(raw: bytes) -> tuple[str, str]:
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw.decode("cp1252"), "cp1252"


def _is_utf16_le(raw: bytes) -> bool:
    if len(raw) < 8 or len(raw) % 2:
        return False
    high_bytes = raw[1::2]
    return high_bytes.count(0) >= int(len(high_bytes) * 0.8)


def _same_file(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return False


def _resolve_input_file(args: list[str]) -> Path:
    if args:
        return Path(args[0])
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.update()
        selected = filedialog.askopenfilename(
            title="Select CPU-Z report",
            filetypes=[
                ("CPU-Z reports", "*.txt *.htm *.html"),
                ("Text", "*.txt"),
                ("HTML", "*.htm *.html"),
                ("All files", "*.*"),
            ],
        )
        root.destroy()
    except Exception as exc:
        raise SystemExit(
            f"Error: could not open a file dialog ({exc}). Pass a file path instead."
        ) from exc
    if not selected:
        raise SystemExit("Error: no input file provided.")
    return Path(selected)


def _summary(
    outfile: Path,
    logfile: Path,
    changes: list[Change],
    skips: list[Skip],
) -> str:
    if changes:
        first = f"Removed {len(changes)} value(s)."
    else:
        first = "No private values were removed."
    lines = [
        first,
        f"Sanitized report: {outfile.name}",
        f"Scrub log: {logfile.name}",
        "Both are in the same folder as the original.",
        "The log lists the original private values. Do not share the log.",
    ]
    if not changes and skips:
        lines.insert(1, f"{len(skips)} field(s) were already generic placeholders.")
    return "\n".join(lines)


def _announce(message: str) -> None:
    if sys.stdout is not None:
        print(message)
    if _use_popup():
        _popup(message)


def _fail(message: str) -> None:
    if _use_popup():
        _popup(message)
    raise SystemExit(message)


def _use_popup() -> bool:
    stream = sys.stdout
    if stream is None:
        return True
    isatty = getattr(stream, "isatty", None)
    if isatty is None:
        return True
    try:
        return not bool(isatty())
    except Exception:
        return True


def _popup(message: str) -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("CPU-Z Scrubber", message)
        root.destroy()
    except Exception:
        pass


if __name__ == "__main__":
    sys.exit(main())
