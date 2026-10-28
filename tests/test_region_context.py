from types import SimpleNamespace
from siglens.region_context import hexdump, _layout


def test_hexdump_offsets():
    lines = hexdump(b"ABCD", base_offset=0x1000)
    assert lines[0].startswith("00001000")
    assert "41 42 43 44" in lines[0]


def test_layout_strips_pe_section_nul_padding(monkeypatch):
    import siglens.region_context as region_context

    section = SimpleNamespace(
        Name=b".text\x00\x00\x00",
        PointerToRawData=1,
        SizeOfRawData=2,
        VirtualAddress=0x1000,
    )
    fake_pe = SimpleNamespace(
        sections=[section],
        OPTIONAL_HEADER=SimpleNamespace(ImageBase=0x140000000, SizeOfHeaders=1),
        get_overlay_data_start_offset=lambda: None,
    )
    monkeypatch.setattr(region_context.pefile, "PE", lambda **kwargs: fake_pe)
    assert _layout(b"abc")["sections"][0]["name"] == ".text"
