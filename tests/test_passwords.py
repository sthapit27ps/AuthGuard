from app.security import passwords, policy

# sthapit27ps


def test_hash_is_argon2id_and_salted():
    a = passwords.hash_password("correct horse battery staple")
    b = passwords.hash_password("correct horse battery staple")
    assert a.startswith("$argon2id$")
    assert a != b  # random salt each time


def test_verify_accepts_right_and_rejects_wrong():
    h = passwords.hash_password("one-two-three-four-five")
    assert passwords.verify_password(h, "one-two-three-four-five")
    assert not passwords.verify_password(h, "one-two-three-four-six")
    assert not passwords.verify_password("not a hash at all", "anything")


def test_unicode_forms_hash_the_same():
    composed = "café-orbit-lantern-quiet"
    decomposed = "café-orbit-lantern-quiet"
    h = passwords.hash_password(composed)
    assert passwords.verify_password(h, decomposed)


def test_needs_rehash_flags_weaker_params():
    from argon2 import PasswordHasher

    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("x" * 14)
    assert passwords.needs_rehash(weak)
    assert not passwords.needs_rehash(passwords.hash_password("x" * 14))


def test_policy_rejects_short():
    r = policy.evaluate("Short1!")
    assert not r.ok
    assert any("at least" in p for p in r.problems)


def test_policy_rejects_common_even_when_long_enough():
    r = policy.evaluate("password123456")
    assert not r.ok
    assert any("common" in p for p in r.problems)


def test_policy_rejects_email_and_name():
    r = policy.evaluate("samantha-rivers-2026-x", email="samantha@example.com", name="Sam")
    assert not r.ok
    assert any("name and email" in p for p in r.problems)


def test_policy_accepts_a_passphrase():
    r = policy.evaluate("violet-lantern-orbit-quiet-9", email="sam@example.com", name="Sam")
    assert r.ok and r.score >= 3 and r.label in ("Good", "Strong")


def test_policy_empty_password():
    r = policy.evaluate("")
    assert not r.ok
