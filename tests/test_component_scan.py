from siglens.component_scan import component_scan

def test_component_scan_symbol_exists():
    assert callable(component_scan)
