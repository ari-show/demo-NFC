import pytest

import main


def test_help_exits_cleanly(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["main.py", "--help"])
    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 0
    assert "--reveal" in capsys.readouterr().out
