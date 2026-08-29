import pytest
from detector.url_analyzer import URLAnalyzer


def test_ip_address_url():
    res = URLAnalyzer.analyze_single_url("http://192.168.1.100/login/auth.php")
    assert res.has_ip is True
    assert res.risk_score >= 40.0
    assert any("Raw IP address" in r for r in res.risk_reasons)


def test_suspicious_tld_url():
    res = URLAnalyzer.analyze_single_url("http://secure-update-portal.xyz/verification")
    assert res.suspicious_tld is True
    assert res.risk_score >= 25.0


def test_url_shortener():
    res = URLAnalyzer.analyze_single_url("https://bit.ly/3xY90P")
    assert res.is_shortener is True
    assert res.risk_score >= 20.0


def test_brand_impersonation_in_url():
    res = URLAnalyzer.analyze_single_url("http://paypal-resolution-center.fake-domain.top/signin")
    assert res.risk_score >= 50.0
    assert any("brand impersonation" in r.lower() for r in res.risk_reasons)


def test_punycode_url():
    res = URLAnalyzer.analyze_single_url("http://xn--pypal-4ve.com/account")
    assert res.has_punycode is True
    assert res.risk_score >= 30.0


def test_benign_clean_url():
    res = URLAnalyzer.analyze_single_url("https://meet.google.com/abc-defg-hij")
    assert res.is_https is True
    assert res.risk_score == 0.0
