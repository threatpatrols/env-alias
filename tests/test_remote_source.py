import pytest

from env_alias.lib.generator import EnvAliasGenerator


def test_sample_remote_text_01(http_file_server, capsys, config_file):
    yaml = f"""
    sample_remote_text_01:
        source: '{http_file_server}/144disk.txt'
        selector: 1
    """

    f = config_file(yaml)
    EnvAliasGenerator(config_file=f).generate()

    captured = capsys.readouterr().out.rstrip()
    assert ' export "sample_remote_text_01"=' in captured
    assert "line one" in captured


def test_sample_remote_json_01(http_file_server, capsys, config_file):
    yaml = f"""
    sample_remote_json_01:
        source: '{http_file_server}/data.json'
        selector: '.prefixes[2].ip_prefix'
    """

    f = config_file(yaml)
    EnvAliasGenerator(config_file=f).generate()

    captured = capsys.readouterr().out.rstrip()
    assert ' export "sample_remote_json_01"=' in captured
    assert "2001:db8::/32" in captured


def test_sample_remote_json_02(http_file_server, capsys, config_file):
    yaml = f"""
    sample_remote_json_01:
        source: '{http_file_server}/data.json'
        selector: 'prefixes.2.ip_prefix'
    """

    f = config_file(yaml)
    EnvAliasGenerator(config_file=f).generate()

    captured = capsys.readouterr().out.rstrip()
    assert ' export "sample_remote_json_01"=' in captured
    assert "2001:db8::/32" in captured


@pytest.mark.network
def test_sample_remote_live_network_01(capsys, config_file):
    """Opt-in real-network smoke test.

    Excluded from the default ``make test`` run (marker ``network``); only run
    explicitly (or via ``make test-all`` / CI) when network access is desired.
    """
    yaml = """
    sample_remote_live_01:
        source: 'https://ip-ranges.amazonaws.com/ip-ranges.json'
        selector: '.prefixes[2].ip_prefix'
    """

    f = config_file(yaml)
    EnvAliasGenerator(config_file=f).generate()

    captured = capsys.readouterr().out.rstrip()
    assert ' export "sample_remote_live_01"=' in captured
    assert len(captured) >= 40


def test_remote_http_404_raises_envalias_exception(http_file_server):
    from env_alias.exceptions import EnvAliasException
    from env_alias.lib.source import EnvAliasSource

    with pytest.raises(EnvAliasException, match="Failed to fetch remote source"):
        EnvAliasSource.remote(f"{http_file_server}/does-not-exist.txt")


def test_remote_redirect_handler_blocks_disallowed_scheme_and_https_downgrade():
    import urllib.request

    from env_alias.exceptions import EnvAliasException
    from env_alias.lib.source import _SafeRedirectHandler

    handler = _SafeRedirectHandler()
    https_req = urllib.request.Request("https://example.com/secret")
    with pytest.raises(EnvAliasException, match="disallowed scheme"):
        handler.redirect_request(https_req, None, 302, "Found", {}, "ftp://evil.example/file")
    with pytest.raises(EnvAliasException, match="HTTPS-to-HTTP"):
        handler.redirect_request(https_req, None, 302, "Found", {}, "http://example.com/secret")
