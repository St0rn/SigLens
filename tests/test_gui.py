def test_gui_module_is_importable_without_creating_a_window():
    from siglens.gui import SigLensApp, launch_gui

    assert SigLensApp is not None
    assert callable(launch_gui)
