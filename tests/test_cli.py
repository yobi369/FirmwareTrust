from firmwaretrust.cli import main


def test_help_output(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["firmwaretrust", "--help"])
    try:
        main()
    except SystemExit as exc:
        assert exc.code == 0
    assert "Sign a firmware file" in capsys.readouterr().out
