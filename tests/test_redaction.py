"""Secret redaction tests — masking at trust boundaries."""

from __future__ import annotations

from sentinel.redact import mask_uri, redact


def test_aws_key_masked():
    assert redact("AKIAIOSFODNN7EXAMPLE") == "<AWS_ACCESS_KEY>"


def test_github_token_masked():
    assert redact("ghp_0123456789abcdefghijklmnop") == "<GITHUB_TOKEN>"


def test_openai_key_masked():
    assert redact("sk-proj-0123456789abcdef0123456789abcdef") == "<OPENAI_TOKEN>"


def test_google_api_key_masked():
    assert redact("AIzaSyD-Pm0f1vFBJu1vTdqB") == "<GOOGLE_API_KEY>"


def test_password_kv_masked():
    out = redact("password = 'hunter2secret'")
    assert "<REDACTED>" in out
    assert "hunter2secret" not in out


def test_api_key_kv_masked():
    out = redact('api_key: "AbCd1234567890AbCd123456789"')
    assert "<REDACTED>" in out
    assert "AbCd1234567890" not in out


def test_mongo_uri_creds_masked():
    uri = "mongodb://demo_user:demo_pass1@cluster0.mongodb.net/db"
    out = mask_uri(uri)
    assert "demo_pass1" not in out
    assert "demo_user" not in out
    assert "cluster0.mongodb.net" in out


def test_private_key_masked():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA1qOKEDrTwVKGvYC7VYfGGnIxIDIq\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    out = redact(pem)
    assert "<PRIVATE_KEY>" in out
    assert "MIIEpAIBAA" not in out


def test_pure_function_no_mutation():
    s = "password = 'hunter2secret'"
    _ = redact(s)
    assert s == "password = 'hunter2secret'"


def test_empty_string_safe():
    assert redact("") == ""


def test_plain_text_untouched():
    text = "def greet(name):\n    return f'hello {name}'\n"
    assert redact(text) == text