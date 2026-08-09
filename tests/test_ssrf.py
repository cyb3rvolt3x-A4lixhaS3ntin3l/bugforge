from gungnir.vulns.ssrf import SsrfHelper, CLOUD_METADATA


def test_metadata_payloads_cover_clouds():
    payloads = SsrfHelper().metadata_payloads()
    assert len(payloads) == len(CLOUD_METADATA)
    types = [p.technique for p in payloads]
    assert "metadata" in types


def test_bypass_payloads_include_variants():
    payloads = SsrfHelper().bypass_payloads()
    techniques = [p.technique for p in payloads]
    assert any("decimal" in t for t in techniques)
    assert any("octal" in t for t in techniques)
    assert any("ipv6" in t for t in techniques)


def test_callback_payloads_use_host():
    payloads = SsrfHelper().callback_payloads("evil.example")
    assert all("evil.example" in p.payload for p in payloads)
    schemes = [p.technique for p in payloads]
    assert any("http" in s for s in schemes)


def test_detect_internal_indicators_private_ip():
    helper = SsrfHelper()
    body = "instance-id: i-12345  ami-id: ami-67890  ip 10.0.0.5"
    indicators = helper.detect_internal_indicators(body)
    assert any("private_ip" in i for i in indicators)
    assert any("metadata_content" in i for i in indicators)


def test_detect_internal_indicators_clean():
    helper = SsrfHelper()
    assert helper.detect_internal_indicators("just a normal 8.8.8.8 page") == []


def test_build_url_replaces_param():
    helper = SsrfHelper()
    new = helper.build_url("https://api.example.com/fetch?page=1&url=legit", "url", "http://evil")
    assert "url=http%3A%2F%2Fevil" in new or "url=http://evil" in new
    assert "page=1" in new


def test_build_url_adds_missing_param():
    helper = SsrfHelper()
    new = helper.build_url("https://api.example.com/fetch", "url", "http://evil")
    assert "url=" in new
