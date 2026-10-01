from siglens.iocs import extract_iocs

def test_iocs():
    x = extract_iocs(["https://example.org/a 192.168.1.20 C:\\Temp\\a.exe"])
    assert "https://example.org/a" in x["urls"]
    assert "192.168.1.20" in x["ipv4"]
    assert "example.org" in x["domains"]
