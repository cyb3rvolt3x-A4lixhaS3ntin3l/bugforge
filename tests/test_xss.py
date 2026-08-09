import pytest
from bugforge.vulns.xss import XssPayloadGen, MUTATIONS


def test_base_payloads_nonempty():
    gen = XssPayloadGen()
    assert len(gen.base()) > 10


def test_generate_includes_mutations():
    gen = XssPayloadGen()
    base = gen.generate(mutate=False)
    mutated = gen.generate(mutate=True)
    assert len(mutated) > len(base)


def test_generate_dedupes():
    gen = XssPayloadGen()
    out = gen.generate(mutate=True)
    assert len(out) == len(set(out))


def test_mutate_all_strategies():
    gen = XssPayloadGen()
    result = gen.mutate("<script>alert(1)</script>", strategy="all")
    assert len(result) == len(MUTATIONS)


def test_mutate_single_strategy():
    gen = XssPayloadGen()
    result = gen.mutate("<script>", strategy="url")
    assert len(result) == 1
    assert "%3C" in result[0]  # url-encoded <


def test_max_count_respected():
    gen = XssPayloadGen()
    out = gen.generate(mutate=True, max_count=5)
    assert len(out) == 5


def test_check_reflection_plain():
    gen = XssPayloadGen()
    assert gen.check_reflection("hello <script>alert(1)</script>", "<script>alert(1)</script>")


def test_check_reflection_encoded():
    gen = XssPayloadGen()
    payload = "<script>alert(1)</script>"
    encoded = "%3Cscript%3Ealert(1)%3C/script%3E"
    assert gen.check_reflection(encoded, payload)


def test_check_reflection_negative():
    gen = XssPayloadGen()
    assert not gen.check_reflection("nothing here", "<script>alert(1)</script>")


def test_custom_payloads():
    gen = XssPayloadGen(payloads=["<custom>"])
    assert gen.base() == ["<custom>"]
