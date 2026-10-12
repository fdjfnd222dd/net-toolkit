import pytest

from net_toolkit import samples


def test_examples_resolve_from_checkout():
    assert samples.example("configs", "edge-rtr1.cfg").is_file()
    assert samples.examples_dir().name == "examples"


def test_packaged_location_wins(tmp_path, monkeypatch):
    (tmp_path / "examples").mkdir()
    monkeypatch.setattr(samples, "_HERE", tmp_path)
    assert samples.examples_dir() == tmp_path / "examples"


def test_missing_example():
    with pytest.raises(FileNotFoundError, match="bundled example missing"):
        samples.example("nope.cfg")
