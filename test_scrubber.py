"""Tests for CPU-Z report scrubbing. Importing this file does not open a dialog."""

import tempfile
import unittest
from pathlib import Path

from scrubber import (
    Change,
    NotAReportError,
    decode_bytes,
    output_paths,
    render_log,
    scrub_file,
    scrub_text,
)

SYSTEM_SERIAL = "ABC1234"
REAL_UUID = "4C4C4544-0044-3010-8044-B4C04F563332"
NIL_UUID = "00000000-0000-0000-0000-000000000000"
BOARD = "CN7220068S00A1"
CHASSIS = "CHAS-999"
ASSET = "ASSET-777"
MEM = "1234ABCD"
OEM = "1[054D] 7[ABC1234] 14[1]"
TOKEN_OEM = "PF0ABC12"
DISK = "S5GXNX0T123456A"
DISPLAY = "K1LMQS123456"
PRODUCT_ID = "00342-00000-00000-AAOEM"
USER = "Alice"
HOST = "ALICE-PC"
DOMAIN = "CONTOSO"
SN = "SN-42"
USER_PATH = "C:\\Users\\Alice"
MAC_FIELD = "00:1A:2B:3C:4D:5E"
MAC_DASH = "AA-BB-CC-DD-EE-FF"
MAC_COLON = "11:22:33:44:55:66"
EMAIL = "alice@example.com"
SID = "S-1-5-21-1004336348-1177238915-682003330-512"
DELL = "7[ZZZ9999]"
DASH = "-" * 73

EXPECTED = [
    SYSTEM_SERIAL,
    REAL_UUID,
    BOARD,
    CHASSIS,
    ASSET,
    MEM,
    OEM,
    TOKEN_OEM,
    DISK,
    DISPLAY,
    PRODUCT_ID,
    USER,
    HOST,
    DOMAIN,
    SN,
    USER_PATH,
    MAC_FIELD,
    EMAIL,
    SID,
    DELL,
    MAC_DASH,
    MAC_COLON,
]

EXPECTED_SKIPS = [
    "WORKGROUP",
    "To be filled by O.E.M.",
    NIL_UUID,
    "No Asset Tag",
    "00000000",
    "(empty)",
]

KEPT = [
    "AMD Ryzen 5 3600",
    "36.0 x 99.8 MHz",
    "ID = 0",
    "Dell Inc.",
    "XPS 15 9500",
    "09A2",
    "0TYFRC",
    "M471A1K43DB1-CWE",
    "Dell System",
    "Samsung SSD 980 PRO 1TB",
    "5B2QGXA7",
    "Generic PnP Monitor",
    "Microsoft Windows 10 (10.0) Professional 64-bit",
    "To be filled by O.E.M.",
    NIL_UUID,
    "No Asset Tag",
    "WORKGROUP",
    "00:00:00:00:00:00",
    "C:\\Users\\Public\\Desktop",
    "C:\\Users\\[SCRUBBED_USER]\\Desktop\\cpu-z.txt",
    DASH,
]

REMOVED = [
    SYSTEM_SERIAL,
    REAL_UUID,
    "054D",
    BOARD,
    CHASSIS,
    ASSET,
    MEM,
    TOKEN_OEM,
    DISK,
    DISPLAY,
    PRODUCT_ID,
    "Alice",
    "ALICE",
    "alice",
    DOMAIN,
    SN,
    MAC_FIELD,
    EMAIL,
    "example.com",
    "S-1-5-21",
    "ZZZ9999",
    MAC_DASH,
    MAC_COLON,
]


def sample_report() -> str:
    lines = [
        "CPU-Z TXT Report",
        DASH,
        "",
        "Processors Information",
        DASH,
        "Socket 1\t\tID = 0",
        "\tName\tAMD Ryzen 5 3600",
        "\tSpecification\tAMD Ryzen 5 3600 6-Core Processor",
        "\tMultiplier x Bus Speed\t36.0 x 99.8 MHz",
        "",
        "DMI System Information",
        "\tmanufacturer\tDell Inc.",
        "\tproduct\tXPS 15 9500",
        "\tserial\t" + SYSTEM_SERIAL,
        "\tUUID\t" + REAL_UUID,
        "\tSKU\t09A2",
        "\tfamily\tXPS",
        "",
        "DMI Baseboard",
        "\tvendor\tDell Inc.",
        "\tmodel\t0TYFRC",
        "\tserial\t" + BOARD,
        "",
        "DMI System Enclosure",
        "\tchassis type\tNotebook",
        "\tchassis serial\t" + CHASSIS,
        "\tasset tag\t" + ASSET,
        "",
        "DMI Memory Device",
        "\tmanufacturer\tSamsung",
        "\tserial\t" + MEM,
        "\tpart number\tM471A1K43DB1-CWE",
        "",
        "DMI OEM Strings",
        "\tString 1\tDell System",
        "\tString 2\t" + OEM,
        "\tString 3\t" + TOKEN_OEM,
        "",
        "Storage",
        "Drive\t0",
        "\tName\tSamsung SSD 980 PRO 1TB",
        "\tSerial Number\t" + DISK,
        "\tFirmware Revision\t5B2QGXA7",
        "",
        "Display 0",
        "\tName\tGeneric PnP Monitor",
        "\tSerial\t" + DISPLAY,
        "",
        "Software",
        "\tWindows Version\tMicrosoft Windows 10 (10.0) Professional 64-bit",
        "\tProduct ID\t" + PRODUCT_ID,
        "\tUser Name: " + USER,
        "\tComputer Name: " + HOST,
        "\tDomain Name\t" + DOMAIN,
        "\tSerial Number: " + SN,
        "\tWorkgroup\tWORKGROUP",
        "",
        "Placeholders",
        "\tserial\tTo be filled by O.E.M.",
        "\tUUID\t" + NIL_UUID,
        "\tasset tag\tNo Asset Tag",
        "\tserial\t00000000",
        "\tserial\t",
        "",
        "Notes",
        "\tpath\t" + USER_PATH + "\\Desktop\\cpu-z.txt",
        "\tpublic path\tC:\\Users\\Public\\Desktop",
        "\tmac\t" + MAC_FIELD,
        "\tzero mac\t00:00:00:00:00:00",
        "\towner email\t" + EMAIL,
        "\tsid\t" + SID,
        "Seen tag " + DELL + " here",
        "Adapter " + MAC_DASH,
        "Adapter " + MAC_COLON,
    ]
    return "\n".join(lines) + "\n"


class ScrubberTests(unittest.TestCase):
    def test_tab_separated_serial_is_replaced(self) -> None:
        cleaned, changes, _ = scrub_text("serial\tSECRET99\r\n")
        self.assertEqual(cleaned, "serial\t[SCRUBBED_SERIAL]\r\n")
        self.assertEqual(changes[0].original, "SECRET99")
        self.assertEqual(changes[0].kind, "SERIAL")

        cleaned, _, _ = scrub_text("serial\tSECRET99")
        self.assertEqual(cleaned, "serial\t[SCRUBBED_SERIAL]")

    def test_placeholder_fields_stay_and_are_recorded(self) -> None:
        text = "\tserial\tTo be filled by O.E.M.\n\tUUID\t" + NIL_UUID + "\n"
        cleaned, changes, skips = scrub_text(text)
        self.assertEqual(cleaned, text)
        self.assertEqual(changes, [])
        self.assertEqual([skip.value for skip in skips], ["To be filled by O.E.M.", NIL_UUID])

    def test_cpu_z_report(self) -> None:
        original = sample_report()
        cleaned, changes, skips = scrub_text(original)

        self.assertNotEqual(cleaned, original)
        self.assertEqual([change.original for change in changes], EXPECTED)
        self.assertEqual([skip.value for skip in skips], EXPECTED_SKIPS)
        for secret in REMOVED:
            self.assertNotIn(secret, cleaned)
        for kept in KEPT:
            self.assertIn(kept, cleaned)
        self.assertIn("\tserial\t00000000", cleaned)

        by_original = {change.original: change for change in changes}
        self.assertEqual(by_original[SYSTEM_SERIAL].section, "DMI System Information")
        self.assertEqual(by_original[SYSTEM_SERIAL].kind, "SERIAL")
        self.assertEqual(by_original[REAL_UUID].kind, "UUID")
        self.assertEqual(by_original[OEM].section, "DMI OEM Strings")
        self.assertEqual(by_original[DISK].section, "Drive 0")
        self.assertEqual(by_original[DISPLAY].section, "Display 0")
        self.assertEqual(by_original[USER].section, "Software")
        self.assertEqual(by_original[USER].kind, "USER")
        self.assertEqual(by_original[HOST].kind, "HOST")
        self.assertEqual(by_original[ASSET].kind, "ASSET")
        self.assertEqual(by_original[USER_PATH].section, "Notes")
        self.assertEqual(by_original[USER_PATH].field, "user path")
        self.assertEqual(by_original[EMAIL].kind, "EMAIL")
        self.assertEqual(by_original[SID].kind, "SID")
        self.assertEqual(by_original[DELL].field, "dell oem id")

        again, changes_again, skips_again = scrub_text(cleaned)
        self.assertEqual(again, cleaned)
        self.assertEqual(changes_again, [])
        self.assertEqual(skips_again, skips)

    def test_html_rows(self) -> None:
        html = """<html><body><table>
<TR><TD COLSPAN=2><FONT COLOR=#FFFFFF>DMI System Information</FONT></TD></TR>
<TR><TD><FONT>manufacturer</FONT></TD><TD><FONT>Dell Inc.</FONT></TD></TR>
<TR><TD><FONT>serial</FONT></TD><TD><FONT>SECRET99</FONT></TD></TR>
<TR><TD><FONT>UUID</FONT></TD><TD><FONT>12345678-1234-1234-1234-123456789abc</FONT></TD></TR>
</table></body></html>
"""
        cleaned, changes, _ = scrub_text(html)
        self.assertNotIn("SECRET99", cleaned)
        self.assertNotIn("12345678-1234-1234-1234-123456789abc", cleaned)
        self.assertIn("Dell Inc.", cleaned)
        serial = next(change for change in changes if change.original == "SECRET99")
        self.assertEqual(serial.section, "DMI System Information")
        self.assertEqual(serial.kind, "SERIAL")

    def test_multiline_html_row(self) -> None:
        html = "<table>\n<TR>\n<TD>serial</TD>\n<TD>SECRET99</TD>\n</TR>\n</table>\n"
        cleaned, changes, _ = scrub_text(html)
        self.assertNotIn("SECRET99", cleaned)
        self.assertEqual(changes[0].original, "SECRET99")
        self.assertEqual(changes[0].line, 2)

    def test_td_pair_without_tr(self) -> None:
        html = "<td>serial</td><td>SECRET99</td>\n<td>model</td><td>0TYFRC</td>\n"
        cleaned, changes, _ = scrub_text(html)
        self.assertEqual([change.original for change in changes], ["SECRET99"])
        self.assertNotIn("SECRET99", cleaned)
        self.assertIn("0TYFRC", cleaned)

    def test_disk_class_id_stays_instance_and_eui_dump_go(self) -> None:
        public_guid = "53f56307-b6bf-11d0-94f2-00a0c91efb8b"
        text = "\n".join(
            [
                "PCI extended capability",
                "\tSerial (EUI-64)\tAABBCCDD-11223344",
                "PCI registers",
                "\t180\t03 00 01 00 44 33 22 11 DD CC BB AA 00 00 00 00",
                "Storage",
                "\tDevice Path\t\\\\?\\scsi#disk&ven_samsung&prod_ssd#4&aabbccdd&0&000000#{"
                + public_guid
                + "}",
                "\tUUID\t{11111111-2222-3333-4444-555555555555}",
            ]
        ) + "\n"
        cleaned, changes, _ = scrub_text(text)
        self.assertNotIn("AABBCCDD-11223344", cleaned)
        self.assertNotIn("44 33 22 11 DD CC BB AA", cleaned)
        self.assertNotIn("aabbccdd", cleaned)
        self.assertIn("03 00 01 00", cleaned)
        self.assertIn("ven_samsung", cleaned)
        self.assertIn(public_guid, cleaned)
        self.assertNotIn("11111111-2222-3333-4444-555555555555", cleaned)
        self.assertIn("#[SCRUBBED_SERIAL]", cleaned)
        fields = {change.field for change in changes}
        self.assertIn("eui bytes", fields)
        self.assertIn("device instance", fields)
        again, changes_again, _ = scrub_text(cleaned)
        self.assertEqual(again, cleaned)
        self.assertEqual(changes_again, [])

    def test_braced_uuid(self) -> None:
        text = "id {12345678-1234-1234-1234-123456789abc} end\n"
        cleaned, changes, _ = scrub_text(text)
        self.assertEqual(changes[0].original, "{12345678-1234-1234-1234-123456789abc}")
        self.assertIn("[SCRUBBED_UUID]", cleaned)
        self.assertNotIn("12345678", cleaned)

        kept, changes, _ = scrub_text("id {00000000-0000-0000-0000-000000000000} end\n")
        self.assertEqual(changes, [])
        self.assertIn("{00000000-0000-0000-0000-000000000000}", kept)

    def test_decodes_utf16_without_treating_utf8_as_utf16(self) -> None:
        utf8 = "\tserial\tSECRET16\n".encode("utf-8")
        self.assertEqual(decode_bytes(utf8)[1], "utf-8")

        text, encoding = decode_bytes("\tserial\tSECRET16\n".encode("utf-16"))
        self.assertEqual(encoding, "utf-16")
        self.assertNotIn("\x00", text)
        cleaned, _, _ = scrub_text(text)
        self.assertNotIn("SECRET16", cleaned)

        text, encoding = decode_bytes("\tserial\tSECRET16\n".encode("utf-16-le"))
        self.assertEqual(encoding, "utf-16-le")
        self.assertIn("SECRET16", text)

        text, encoding = decode_bytes(b"\tserial\tABC\xe9\n")
        self.assertEqual(encoding, "cp1252")
        cleaned, changes, _ = scrub_text(text)
        self.assertNotIn("ABC", cleaned)
        self.assertTrue(changes)

    def test_output_names_and_log_omit_the_user_path(self) -> None:
        source = Path("C:/Users/Alice/report.txt")
        report, log = output_paths(source)
        self.assertEqual(report, source.with_name("sanitized_report.txt"))
        self.assertEqual(log, source.with_name("scrublog_report.txt"))

        rendered = render_log(
            source,
            report,
            "utf-16",
            [Change(4, "DMI System Information", "serial", "SERIAL", "SECRET99", "[SCRUBBED_SERIAL]")],
            [],
        )
        self.assertIn("Source file: report.txt", rendered)
        self.assertIn("Sanitized file: sanitized_report.txt", rendered)
        self.assertIn("Read as: utf-16", rendered)
        self.assertIn("SECRET99", rendered)
        self.assertIn("not this log", rendered)
        self.assertNotIn("Users", rendered)
        self.assertNotIn("Alice", rendered)

    def test_scrub_file_writes_utf8_and_log(self) -> None:
        root = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(dir=root) as folder:
            folder_path = Path(folder)
            source = folder_path / "report.txt"
            source.write_bytes("\tserial\tSECRET16\n".encode("utf-16"))
            report, log = output_paths(source)
            changes, _ = scrub_file(source, report, log)
            data = report.read_bytes()
            self.assertNotIn(b"\x00", data)
            self.assertNotIn(b"SECRET16", data)
            self.assertIn(b"[SCRUBBED_SERIAL]", data)
            log_text = log.read_text(encoding="utf-8")
            self.assertIn("SECRET16", log_text)
            self.assertIn("Read as: utf-16", log_text)
            self.assertIn("not this log", log_text)
            self.assertEqual(changes[0].original, "SECRET16")

    def test_binary_is_not_written(self) -> None:
        root = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(dir=root) as folder:
            folder_path = Path(folder)
            source = folder_path / "junk.bin"
            source.write_bytes(bytes(range(1, 32)) * 5)
            report, log = output_paths(source)
            with self.assertRaises(NotAReportError):
                scrub_file(source, report, log)
            self.assertFalse(report.exists())
            self.assertFalse(log.exists())


if __name__ == "__main__":
    unittest.main()
