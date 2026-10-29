from pathlib import Path
import struct
from types import SimpleNamespace

from siglens.pe_analyzer import analyze_pe


def test_unexpected_parser_failure_is_reported(monkeypatch):
    import siglens.pe_analyzer as pe_analyzer

    def fail(**kwargs):
        raise OSError("parser failure")

    monkeypatch.setattr(pe_analyzer.pefile, "PE", fail)
    result = analyze_pe(Path("sample.exe"), b"MZ")
    assert result["is_pe"] is False
    assert result["error"] == "OSError: parser failure"


def test_security_posture_reports_mitigations_sections_signature_and_pdb(monkeypatch):
    import siglens.pe_analyzer as pe_analyzer

    data = bytearray(512)
    pdb_blob = b"RSDS" + bytes.fromhex("00112233445566778899aabbccddeeff") + struct.pack("<I", 3) + b"C:\\build\\demo.pdb\x00"
    data[300:300 + len(pdb_blob)] = pdb_blob
    struct.pack_into("<IHH", data, 400, 16, 0x0200, 0x0002)

    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(16)]
    directories[4] = SimpleNamespace(VirtualAddress=400, Size=16)
    directories[5] = SimpleNamespace(VirtualAddress=0x3000, Size=96)
    section = SimpleNamespace(
        Name=b".text\x00\x00\x00",
        VirtualAddress=0x1000,
        PointerToRawData=0x200,
        SizeOfRawData=0x200,
        Misc_VirtualSize=0x180,
        Characteristics=0xE0000020,
        get_data=lambda: b"\x90" * 32,
    )
    debug = SimpleNamespace(struct=SimpleNamespace(
        Type=2,
        PointerToRawData=300,
        SizeOfData=len(pdb_blob),
        TimeDateStamp=1_700_000_000,
    ))

    class FakePE:
        FILE_HEADER = SimpleNamespace(Machine=0x8664, TimeDateStamp=1_700_000_000, Characteristics=0x0002)
        OPTIONAL_HEADER = SimpleNamespace(
            Magic=0x20B,
            ImageBase=0x140000000,
            AddressOfEntryPoint=0x1010,
            DllCharacteristics=0x40 | 0x100 | 0x4000,
            DATA_DIRECTORY=directories,
        )
        sections = [section]
        DIRECTORY_ENTRY_DEBUG = [debug]

        @staticmethod
        def get_overlay_data_start_offset():
            return 400

        @staticmethod
        def get_imphash():
            return "0123456789abcdef0123456789abcdef"

    monkeypatch.setattr(pe_analyzer.pefile, "PE", lambda **kwargs: FakePE())
    result = analyze_pe(Path("demo.exe"), bytes(data))

    assert result["is_pe"] is True
    assert result["timestamp_utc"] == "2023-11-14T22:13:20+00:00"
    assert result["sections"][0]["permissions"] == {
        "read": True,
        "write": True,
        "execute": True,
        "code": True,
    }
    security = result["security"]
    assert security["architecture"] == "x64"
    assert security["mitigations"]["aslr"]["enabled"] is True
    assert security["mitigations"]["dep"]["enabled"] is True
    assert security["mitigations"]["cfg"]["enabled"] is True
    assert security["relocations"]["aslr_effective"] is True
    assert security["authenticode"]["present"] is True
    assert security["authenticode"]["certificate_bounds_valid"] is True
    assert security["authenticode"]["trust_verification_performed"] is False
    assert security["authenticode"]["trust_status"] == "not_checked"
    assert security["debug"][0]["pdb_path"] == "C:\\build\\demo.pdb"
    assert security["entry_point"]["section"] == ".text"
    assert security["section_review"]["writable_executable"] == [".text"]
    assert security["summary"]["high"] == 1
    assert security["imphash"] == "0123456789abcdef0123456789abcdef"
