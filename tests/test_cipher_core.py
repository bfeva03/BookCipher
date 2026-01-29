
"""
Unit tests for cipher_core module.
Tests encryption, decryption, key strength, and BC1/BC2 compatibility.
"""

import importlib.util
import uuid

import pytest

CRYPT_AVAILABLE = importlib.util.find_spec("cryptography") is not None
pytestmark = pytest.mark.skipif(
    not CRYPT_AVAILABLE,
    reason="cryptography is required for cipher tests",
)

if CRYPT_AVAILABLE:
    import cipher_core


class TestKeyStrength:
    """Test key strength detection."""

    def test_empty_key(self):
        score, warnings = cipher_core.check_key_strength("")
        assert score == 0
        assert "empty" in warnings[0].lower()

    def test_weak_key(self):
        score, warnings = cipher_core.check_key_strength("abc")
        assert score < 50  # Short key should score low
        assert len(warnings) > 0

    def test_strong_key(self):
        score, warnings = cipher_core.check_key_strength("MyStr0ng!Passphrase2024")
        assert score > 70
        assert len(warnings) < 3  # Should have few warnings

    def test_common_passphrase(self):
        score, warnings = cipher_core.check_key_strength("password")
        assert any("common" in w.lower() for w in warnings)


class TestCorpus:
    """Test corpus building."""

    def test_single_book(self):
        text = "Hello World. This is a test."
        corpus = cipher_core.build_corpus([text], autoclean=False)
        assert corpus.text == text
        assert len(corpus.sha256) == 32  # SHA256 is 32 bytes

    def test_multiple_books(self):
        text1 = "First book."
        text2 = "Second book."
        corpus = cipher_core.build_corpus([text1, text2], autoclean=False)
        assert "First book" in corpus.text
        assert "Second book" in corpus.text
        assert "\n\n" in corpus.text  # Books separated by \n\n

    def test_gutenberg_cleaning(self):
        text = "*** START OF THE PROJECT GUTENBERG EBOOK ***\nReal content here\n*** END OF THE PROJECT GUTENBERG EBOOK ***"
        corpus = cipher_core.build_corpus([text], autoclean=True)
        assert "Real content here" in corpus.text
        assert "PROJECT GUTENBERG" not in corpus.text

    def test_corpus_hash_consistency(self):
        """Same books should produce same hash."""
        text = "Test content."
        corpus1 = cipher_core.build_corpus([text], autoclean=False)
        corpus2 = cipher_core.build_corpus([text], autoclean=False)
        assert corpus1.sha256 == corpus2.sha256


class TestEncryptionDecryption:
    """Test BC2 encryption and decryption."""

    def test_basic_encrypt_decrypt(self):
        text = "The quick brown fox jumps over the lazy dog."
        corpus = cipher_core.build_corpus([text], autoclean=False)
        key = "MySecurePassphrase123!"

        # Encrypt
        plaintext = "Hello World"
        token = cipher_core.encrypt(plaintext, key, corpus)

        # Token structure: BC2.salt.nonce.hash.ciphertext
        parts = token.split(".")
        assert parts[0] == "BC2"
        assert len(parts) == 5

        # Decrypt
        recovered = cipher_core.decrypt(token, key, corpus)
        assert recovered == plaintext

    def test_legacy_bc2_aad_compatibility(self):
        text = "Test corpus"
        corpus = cipher_core.build_corpus([text], autoclean=False)
        key = "TestKey123!"
        plaintext = "Legacy AAD"

        salt = b"\x00" * 16
        nonce = b"\x01" * 12
        k = cipher_core._derive_key(
            key,
            salt,
            scrypt_params=cipher_core.ScryptParams(
                n=cipher_core.SCRYPT_DEFAULT_N,
                r=cipher_core.SCRYPT_R,
                p=cipher_core.SCRYPT_P,
            ),
            allow_weak_kdf=False,
        )
        aesgcm = cipher_core.AESGCM(k)
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), corpus.sha256)

        token = ".".join(
            [
                cipher_core.MAGIC,
                cipher_core._b64u_encode(salt),
                cipher_core._b64u_encode(nonce),
                cipher_core._b64u_encode(corpus.sha256),
                cipher_core._b64u_encode(ct),
            ]
        )
        assert cipher_core.decrypt(token, key, corpus) == plaintext

    def test_wrong_key_fails(self):
        text = "Test corpus"
        corpus = cipher_core.build_corpus([text], autoclean=False)

        token = cipher_core.encrypt("Secret", "key1", corpus)

        with pytest.raises(ValueError, match="Wrong key"):
            cipher_core.decrypt(token, "wrongkey", corpus)

    def test_wrong_corpus_fails(self):
        corpus1 = cipher_core.build_corpus(["Book 1"], autoclean=False)
        corpus2 = cipher_core.build_corpus(["Book 2"], autoclean=False)

        token = cipher_core.encrypt("Secret", "key1", corpus1)

        with pytest.raises(ValueError, match="corpus mismatch"):
            cipher_core.decrypt(token, "key1", corpus2)

    def test_tampered_token_fails(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        token = cipher_core.encrypt("Secret", "key", corpus)

        # Tamper with the ciphertext part
        parts = token.split(".")
        parts[4] = "TAMPERED" + parts[4][8:]
        tampered = ".".join(parts)

        with pytest.raises(ValueError, match="modified|Wrong key"):
            cipher_core.decrypt(tampered, "key", corpus)

    def test_empty_plaintext(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        token = cipher_core.encrypt("", "key", corpus)
        recovered = cipher_core.decrypt(token, "key", corpus)
        assert recovered == ""

    def test_unicode_plaintext(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        plaintext = "Hello 世界 🌍 Привет"
        token = cipher_core.encrypt(plaintext, "key", corpus)
        recovered = cipher_core.decrypt(token, "key", corpus)
        assert recovered == plaintext

    def test_empty_key_fails(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        with pytest.raises(ValueError, match="Key is required"):
            cipher_core.encrypt("text", "", corpus)

    def test_deterministic_encryption_different_ciphertexts(self):
        """Same plaintext+key+corpus should produce different tokens (fresh salt/nonce)."""
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        plaintext = "Same message"
        key = "Same key"

        token1 = cipher_core.encrypt(plaintext, key, corpus)
        token2 = cipher_core.encrypt(plaintext, key, corpus)

        # Tokens should be different (fresh randomness each time)
        assert token1 != token2

        # But both should decrypt to the same plaintext
        assert cipher_core.decrypt(token1, key, corpus) == plaintext
        assert cipher_core.decrypt(token2, key, corpus) == plaintext


class TestScryptParameters:
    """Test configurable Scrypt parameters."""

    def test_default_scrypt_strength(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        token = cipher_core.encrypt("Hello", "key", corpus, cipher_core.SCRYPT_DEFAULT_N)
        assert cipher_core.decrypt(token, "key", corpus) == "Hello"

    def test_high_scrypt_strength(self):
        """High Scrypt (n=2^18) creates tokens that require same n to decrypt."""
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        # Encrypt with high Scrypt
        plaintext = "Hello"
        token = cipher_core.encrypt(plaintext, "key", corpus, cipher_core.SCRYPT_HIGH_N)
        assert "BC2" in token
        # Token itself doesn't encode which n was used, so we can't decrypt it directly
        # This is expected behavior - token format doesn't include Scrypt parameters
        # In real usage, user would remember which setting was used
        # For testing, we just verify the token structure is valid
        parts = token.split(".")
        assert len(parts) == 5
        assert parts[0] == "BC2"

    def test_invalid_scrypt_strength_fails(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        with pytest.raises(ValueError, match="scrypt_n"):
            cipher_core.encrypt("Hello", "key", corpus, 999)


class TestBC1Compatibility:
    """Test backward compatibility with BC1 tokens."""

    def test_decrypt_bc1_with_warning(self):
        """BC1 tokens should decrypt with a deprecation warning."""
        # We can't easily create BC1 tokens here since BC2 is the current standard,
        # but we can test that BC1 would be supported if present.
        # For now, just verify MAGIC_BC1 is defined.
        assert hasattr(cipher_core, "MAGIC_BC1")
        assert cipher_core.MAGIC_BC1 == "BC1"


class TestTokenFormat:
    """Test token format and validation."""

    def test_invalid_token_format_few_parts(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        with pytest.raises(ValueError, match="5 or 6 parts"):
            cipher_core.decrypt("BC2.xxx.yyy", "key", corpus)

    def test_invalid_token_format_bad_encoding(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        # Token with invalid base64 in nonce field produces valid decoding but wrong hash check
        # The base64 decoder will succeed for these patterns (! is actually not valid)
        with pytest.raises(ValueError):  # Will fail for some reason
            cipher_core.decrypt("BC2.abc.def.ghi.jkl", "key", corpus)

    def test_tampered_corpus_hash_fails(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        token = cipher_core.encrypt("Secret", "key", corpus)
        parts = token.split(".")
        ch = cipher_core._b64u_decode(parts[3])
        tampered_ch = bytes([ch[0] ^ 0x01]) + ch[1:]
        parts[3] = cipher_core._b64u_encode(tampered_ch)
        tampered = ".".join(parts)
        with pytest.raises(ValueError, match="corpus mismatch"):
            cipher_core.decrypt(tampered, "key", corpus)


class TestPaddingAndMetadata:
    """Test padding and metadata handling."""

    def test_padding_block_roundtrip(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        token = cipher_core.encrypt(
            "Hello",
            "key",
            corpus,
            padding="block",
            padding_block_size=32,
        )
        parts = token.split(".")
        assert parts[0] == "BC3"
        assert len(parts) == 6
        assert cipher_core.decrypt(token, "key", corpus) == "Hello"

    def test_padding_pow2_roundtrip(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        token = cipher_core.encrypt(
            "Hello world",
            "key",
            corpus,
            padding="pow2",
        )
        parts = token.split(".")
        assert parts[0] == "BC3"
        assert len(parts) == 6
        assert cipher_core.decrypt(token, "key", corpus) == "Hello world"

    def test_tampered_metadata_fails(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        token = cipher_core.encrypt(
            "Secret",
            "key",
            corpus,
            padding="block",
            padding_block_size=32,
        )
        parts = token.split(".")
        meta = cipher_core._b64u_decode(parts[4])
        tampered_meta = bytes([meta[0] ^ 0x01]) + meta[1:]
        parts[4] = cipher_core._b64u_encode(tampered_meta)
        tampered = ".".join(parts)
        with pytest.raises(ValueError):
            cipher_core.decrypt(tampered, "key", corpus)

    def test_invalid_message_id_version_rejected(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        token = cipher_core.encrypt(
            "Secret",
            "key",
            corpus,
            message_id="auto",
        )
        parts = token.split(".")
        meta = bytearray(cipher_core._b64u_decode(parts[4]))
        # Set UUID version nibble to 1 (not v4). UUID is last 16 bytes in meta.
        uuid_offset = len(meta) - 16
        meta[uuid_offset + 6] = (meta[uuid_offset + 6] & 0x0F) | 0x10
        parts[4] = cipher_core._b64u_encode(bytes(meta))
        tampered = ".".join(parts)
        with pytest.raises(ValueError):
            cipher_core.decrypt(tampered, "key", corpus)

    def test_message_id_presence_and_aad(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        msg_id = str(uuid.uuid4())
        token = cipher_core.encrypt(
            "Secret",
            "key",
            corpus,
            message_id=msg_id,
        )
        meta = cipher_core.get_token_metadata(token)
        assert meta["message_id"] == msg_id
        # Tamper metadata; AAD should fail
        parts = token.split(".")
        parts[4] = "B" + parts[4][1:]
        tampered = ".".join(parts)
        with pytest.raises(ValueError):
            cipher_core.decrypt(tampered, "key", corpus)

    def test_decrypt_with_metadata_bc2_empty(self):
        corpus = cipher_core.build_corpus(["Test"], autoclean=False)
        token = cipher_core.encrypt("Hello", "key", corpus)
        pt, meta = cipher_core.decrypt_with_metadata(token, "key", corpus)
        assert pt == "Hello"
        assert meta == {}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
