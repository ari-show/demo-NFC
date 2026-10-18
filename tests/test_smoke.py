import main


def test_main_prints_greeting(capsys):
    main.main()
    assert "demo-nfc" in capsys.readouterr().out
