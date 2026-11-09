"""PHP exposure/triage (phpestate.py): local version detection against a fake `php` interpreter,
EOL/BEHIND/CURRENT classification against both a faked live feed and the static fallback, and the
remote passive fingerprinter's hard authorization gate (no request without `authorized=True`).

Fast and deterministic: no Docker, and no real network call except the one opportunistic
live-feed test, which skips cleanly (like the Docker-availability checks elsewhere in this repo)
if php.net is not reachable from this environment."""
import os
import stat
import urllib.error
import urllib.request

import pytest

from binoracle.workflows import phpestate as pe


def _write_fake_php(tmp_path, version="8.1.2", name="fakephp", exit_code=0):
    """Un interprete PHP FALSO pero REAL (un script ejecutable de verdad, no un mock de
    subprocess): se invoca con `-v` exactamente como el `probe_php_version` real haria con un
    PHP autentico, igual que `yetDevs/php2shell-triage`'s `fake_php_host.py` hace, salvo que
    aqui es un shell script propio en vez de copiar el suyo."""
    p = tmp_path / name
    p.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"-v\" ]; then\n"
        f"  echo 'PHP {version} (cli) (built: Jan  1 2024 00:00:00) ( NTS )'\n"
        "  echo 'Copyright (c) The PHP Group'\n"
        f"  exit {exit_code}\n"
        "fi\n"
        "exit 1\n"
    )
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(p)


# --- probe_php_version / find_php_binaries -----------------------------------------------------


def test_probe_php_version_parses_real_output(tmp_path):
    php = _write_fake_php(tmp_path, version="8.2.12")
    probed = pe.probe_php_version(php)
    assert probed is not None
    version, raw = probed
    assert version == (8, 2, 12)
    assert "PHP 8.2.12" in raw


def test_probe_php_version_none_for_non_php_binary(tmp_path):
    p = tmp_path / "notphp"
    p.write_text("#!/bin/sh\necho 'not php at all'\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    assert pe.probe_php_version(str(p)) is None


def test_find_php_binaries_direct_file_path(tmp_path):
    php = _write_fake_php(tmp_path)
    found = pe.find_php_binaries([php])
    assert found == [php]


def test_find_php_binaries_walks_directory_bounded_depth(tmp_path):
    deep = tmp_path / "root" / "usr" / "local" / "bin"
    deep.mkdir(parents=True)
    php = _write_fake_php(deep, name="php8.3")
    found = pe.find_php_binaries([str(tmp_path / "root")])
    assert any(os.path.realpath(f) == os.path.realpath(php) for f in found)


def test_find_php_binaries_skips_vendor_and_lookalike_names(tmp_path):
    vendor = tmp_path / "vendor" / "somepkg"
    vendor.mkdir(parents=True)
    _write_fake_php(vendor, name="php")  # inside a skipped dir name -> must not be found
    not_php = tmp_path / "myphpscript.sh"
    not_php.write_text("#!/bin/sh\necho hi\n")
    not_php.chmod(not_php.stat().st_mode | stat.S_IEXEC)
    found = pe.find_php_binaries([str(tmp_path)])
    assert found == []


# --- classify_php_version ------------------------------------------------------------------


def _fake_feed(version: str, supported):
    return {"version": version, "supported_versions": supported}


def test_classify_eol_against_live_feed():
    feed = _fake_feed("8.5.11", ["8.2", "8.3", "8.4", "8.5"])
    bucket, note, source = pe.classify_php_version((7, 4, 33), feed)
    assert bucket == "EOL"
    assert "live release feed" in source
    assert "7.4" in note


def test_classify_behind_and_current_against_live_feed():
    feed = _fake_feed("8.2.34", ["8.2", "8.3", "8.4", "8.5"])
    bucket, _, _ = pe.classify_php_version((8, 2, 10), feed)
    assert bucket == "BEHIND"
    bucket, _, _ = pe.classify_php_version((8, 2, 34), feed)
    assert bucket == "CURRENT"
    bucket, _, _ = pe.classify_php_version((8, 2, 99), feed)  # newer than known latest -> CURRENT
    assert bucket == "CURRENT"


def test_classify_falls_back_to_static_table_when_feed_unreachable():
    # feed=None simulates fetch_live_release_data() degrading honestly after a network failure.
    bucket, note, source = pe.classify_php_version((8, 2, 10), None)
    assert bucket == "BEHIND"
    assert "static fallback table" in source
    assert "may be stale" in source

    bucket, note, source = pe.classify_php_version((7, 4, 33), None)
    assert bucket == "EOL"
    assert "static fallback table" in source


def test_classify_unknown_branch_in_fallback_is_not_claimed_current():
    # A branch inside the "currently supported" range by number (>= 8.2) but not present in the
    # static table at all must come back UNKNOWN, never silently CURRENT or EOL -- "no data"
    # must stay "no data", not get rounded up or down into a false claim.
    bucket, note, source = pe.classify_php_version((8, 9, 0), None)
    assert bucket == "UNKNOWN"
    assert "inconclusive" in note


# --- scan_php_local (Finding-producing entry point) --------------------------------------------


def test_scan_php_local_classifies_eol_binary(tmp_path, monkeypatch):
    php = _write_fake_php(tmp_path, version="7.4.33")
    # Force the static fallback path so this test needs no network at all.
    monkeypatch.setattr(pe, "fetch_live_release_data", lambda branch, timeout=8.0: None)
    findings = pe.scan_php_local([php], lang="en")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert f.verdict == "grounded"
    assert "EOL" in f.title
    assert php in f.location


def test_scan_php_local_classifies_current_binary(tmp_path, monkeypatch):
    php = _write_fake_php(tmp_path, version="8.5.11")
    monkeypatch.setattr(pe, "fetch_live_release_data",
                         lambda branch, timeout=8.0: _fake_feed("8.5.11", ["8.2", "8.3", "8.4", "8.5"]))
    findings = pe.scan_php_local([php], lang="en")
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "CURRENT" in findings[0].title


def test_scan_php_local_no_binaries_found_is_honest_not_a_false_negative(tmp_path):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    findings = pe.scan_php_local([str(empty_dir)], lang="en")
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "does NOT prove PHP is absent" in findings[0].rationale


# --- fingerprint_php_remote: the hard authorization gate ---------------------------------------


def test_remote_fingerprint_sends_nothing_without_authorization(monkeypatch):
    calls = []

    def _spy(*a, **kw):
        calls.append((a, kw))
        raise AssertionError("urlopen must never be called without authorized=True")

    monkeypatch.setattr(urllib.request, "urlopen", _spy)
    findings = pe.fingerprint_php_remote("https://example.invalid", authorized=False, lang="en")
    assert calls == []
    assert len(findings) == 1
    assert "skipped" in findings[0].title.lower()
    assert "--authorized" in findings[0].title


def test_remote_fingerprint_authorized_sends_exactly_one_request_and_parses_header(monkeypatch):
    calls = []

    class _FakeResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def getheaders(self):
            return [("Server", "Apache/2.4.41 (Ubuntu) PHP/8.1.2"),
                    ("X-Powered-By", "PHP/8.1.2"),
                    ("Set-Cookie", "PHPSESSID=abc123; path=/")]

    def _fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        return _FakeResp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(pe, "fetch_live_release_data", lambda branch, timeout=8.0: None)

    findings = pe.fingerprint_php_remote("https://example.invalid/", authorized=True, lang="en")
    assert calls == ["https://example.invalid/"]       # exactly one request, exact URL, no path added
    assert len(findings) == 1
    f = findings[0]
    assert "8.1.2" in f.title
    assert "BEHIND" in f.title or "EOL" in f.title       # 8.1.x is EOL per the static table


def test_remote_fingerprint_no_version_header_is_honest_about_the_limitation(monkeypatch):
    class _FakeResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def getheaders(self):
            return [("Server", "BunnyCDN-ES1-895")]  # no PHP token at all -- real php.net shape

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: _FakeResp())
    findings = pe.fingerprint_php_remote("https://example.invalid/", authorized=True, lang="en")
    assert len(findings) == 1
    assert "No PHP version visible" in findings[0].title
    assert "expose_php" in findings[0].rationale


def test_remote_fingerprint_request_failure_is_reported_not_swallowed(monkeypatch):
    def _raise(req, timeout=None):
        raise urllib.error.URLError("name resolution failed")

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    findings = pe.fingerprint_php_remote("https://example.invalid/", authorized=True, lang="en")
    assert len(findings) == 1
    assert findings[0].verdict == "unverified"
    assert "failed" in findings[0].title.lower()


# --- opportunistic real-network confirmation (skips cleanly if unreachable) ---------------------


def test_live_php_net_feed_is_real_and_parses(tmp_path):
    """Not mocked: confirms the actual php.net endpoint this module relies on is still live and
    still shaped the way classify_php_version expects. Mirrors this repo's Docker-availability
    skip pattern -- skip cleanly (not fail) if this environment can't reach the network."""
    try:
        feed = pe.fetch_live_release_data("8.2", timeout=5.0)
    except Exception:
        feed = None
    if feed is None:
        pytest.skip("php.net release feed unreachable from this environment")
    assert "version" in feed and "supported_versions" in feed
    assert pe._parse_version_str(feed["version"]) is not None
