"""
QuantumShield — Cryptographic Artifact Discovery Tests
Tests:
  - RSA, EC, Ed25519 X.509 Certificate parsing & chains
  - Private key detection (unencrypted vs password-protected)
  - Public key fingerprinting & Key-Certificate correlation
  - Keystores (PKCS#12 & JKS)
  - Config parsing (SSH, Nginx, OpenSSL, Java security)
  - Crypto environment variable redaction
  - PQC algorithm and library detection
  - Static OS and language package discovery
"""

from datetime import datetime, timedelta, timezone
import os
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from app.scanner.container.crypto.cert_parser import CertificateParser
from app.scanner.container.crypto.config_parser import ConfigParser
from app.scanner.container.crypto.key_parser import KeyParser
from app.scanner.container.crypto.keystore_parser import KeystoreParser
from app.scanner.container.crypto.pqc_detector import PQCDetector
from app.scanner.container.binary.binary_inspector import BinaryInspector
from app.scanner.container.packages.crypto_libraries import CryptoLibraryMatcher
from app.scanner.container.packages.language_packages import LanguagePackageParser
from app.scanner.container.packages.os_packages import OSPackageParser
from app.scanner.container.models import PackageObservation


@pytest.fixture
def rsa_key_and_cert():
    """Generate a real RSA key pair and self-signed certificate."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test-service.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QuantumShield Test Org"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(priv, hashes.SHA256())
    )
    return priv, cert


@pytest.fixture
def ec_key_and_cert():
    """Generate an Elliptic Curve (secp256r1) key pair and certificate."""
    priv = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ec-service.local"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(priv, hashes.SHA256())
    )
    return priv, cert


class TestCertificateAndKeyParsing:
    """Test safe parsing of certificates, keys, and their cryptographic correlation."""

    def test_rsa_certificate_parsing(self, tmp_path, rsa_key_and_cert):
        priv, cert = rsa_key_and_cert
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        cert_file = tmp_path / "server.crt"
        cert_file.write_bytes(cert_pem)

        observations = CertificateParser.parse_file(str(cert_file))
        assert len(observations) == 1
        obs = observations[0]

        assert obs.artifact_type == "certificate"
        assert obs.algorithm == "RSA"
        assert obs.key_size == 2048
        assert "sha256" in obs.signature_algorithm.lower()
        assert obs.evidence.get("subject_cn") == "test-service.local"
        assert obs.evidence.get("is_self_signed") is True
        assert obs.evidence.get("expired") is False

    def test_ec_certificate_parsing(self, tmp_path, ec_key_and_cert):
        priv, cert = ec_key_and_cert
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        cert_file = tmp_path / "ec.crt"
        cert_file.write_bytes(cert_pem)

        observations = CertificateParser.parse_file(str(cert_file))
        assert len(observations) == 1
        obs = observations[0]

        assert obs.algorithm == "EC"
        assert obs.key_size == 256
        assert obs.curve == "secp256r1"

    def test_private_key_parsing_and_zero_secret_leakage(self, tmp_path, rsa_key_and_cert):
        priv, _ = rsa_key_and_cert
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        key_file = tmp_path / "server.key"
        key_file.write_bytes(priv_pem)

        observations = KeyParser.parse_file(str(key_file))
        assert len(observations) == 1
        obs = observations[0]

        assert obs.artifact_type == "private_key"
        assert obs.algorithm == "RSA"
        assert obs.key_size == 2048
        assert obs.evidence.get("is_encrypted") is False
        assert "public_key_fingerprint" in obs.evidence

        # CRITICAL: Verify raw private key material is NEVER stored in observation
        obs_dump = obs.model_dump_json()
        assert "PRIVATE KEY" not in obs.evidence.get("public_key_fingerprint", "")
        assert str(priv.private_numbers().d) not in obs_dump

    def test_encrypted_private_key_detection(self, tmp_path, rsa_key_and_cert):
        priv, _ = rsa_key_and_cert
        enc_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"strongpassword123"),
        )

        key_file = tmp_path / "encrypted.key"
        key_file.write_bytes(enc_pem)

        observations = KeyParser.parse_file(str(key_file))
        assert len(observations) == 1
        obs = observations[0]

        assert obs.artifact_type == "private_key"
        assert obs.evidence.get("is_encrypted") is True
        assert obs.evidence.get("status") == "ENCRYPTED_UNINSPECTED"

    def test_key_certificate_cryptographic_correlation(self, tmp_path, rsa_key_and_cert):
        priv, cert = rsa_key_and_cert

        key_file = tmp_path / "mismatched_name.key"
        key_file.write_bytes(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        cert_file = tmp_path / "different_name.crt"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        keys = KeyParser.parse_file(str(key_file))
        certs = CertificateParser.parse_file(str(cert_file))

        correlations = KeyParser.correlate_keys_and_certs(keys, certs)
        assert len(correlations) == 1
        assert correlations[0]["correlation_type"] == "public_key_cryptographic_match"
        assert correlations[0]["key_path"] == str(key_file)
        assert correlations[0]["cert_path"] == str(cert_file)


class TestKeystoreAndTrustStores:
    """Test safe handling of PKCS#12 and JKS stores."""

    def test_jks_magic_detection(self, tmp_path):
        jks_file = tmp_path / "keystore.jks"
        jks_file.write_bytes(b"\xfe\xed\xfe\xed\x00\x00\x00\x02" + b"\x00" * 64)

        observations = KeystoreParser.parse_file(str(jks_file))
        assert len(observations) == 1
        obs = observations[0]
        assert obs.artifact_type == "keystore"
        assert obs.algorithm == "JKS"
        assert obs.evidence.get("status") == "ENCRYPTED_UNINSPECTED"

    def test_pkcs12_passwordless_store(self, tmp_path, rsa_key_and_cert):
        from cryptography.hazmat.primitives.serialization import pkcs12

        priv, cert = rsa_key_and_cert
        p12_bytes = pkcs12.serialize_key_and_certificates(
            name=b"testcert",
            key=priv,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.NoEncryption(),
        )

        p12_file = tmp_path / "service.p12"
        p12_file.write_bytes(p12_bytes)

        observations = KeystoreParser.parse_file(str(p12_file))
        assert len(observations) == 1
        obs = observations[0]
        assert obs.artifact_type == "keystore"
        assert obs.evidence.get("status") == "INSPECTED_EMPTY_PASSWORD"
        assert obs.evidence.get("has_private_key") is True


class TestCryptoConfigsAndEnvVars:
    """Test configuration files and redacted environment variables."""

    def test_sshd_config_extraction(self, tmp_path):
        cfg = tmp_path / "sshd_config"
        cfg.write_text(
            "Port 22\n"
            "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n"
            "KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256\n"
            "MACs hmac-sha2-512-etm@openssh.com\n"
        )

        observations = ConfigParser.parse_file(str(cfg))
        assert len(observations) == 3
        extracted = {obs.evidence.get("setting_name"): obs.evidence.get("algorithms_extracted") for obs in observations}
        assert "ciphers" in extracted
        assert "chacha20-poly1305@openssh.com" in extracted["ciphers"]

    def test_nginx_ssl_extraction(self, tmp_path):
        cfg = tmp_path / "nginx.conf"
        cfg.write_text(
            "http {\n"
            "    ssl_protocols TLSv1.2 TLSv1.3;\n"
            "    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n"
            "    ssl_certificate /etc/ssl/certs/cert.pem;\n"
            "}\n"
        )

        observations = ConfigParser.parse_file(str(cfg))
        assert len(observations) >= 2
        directives = {obs.evidence.get("setting_name") for obs in observations}
        assert "ssl_protocols" in directives
        assert "ssl_ciphers" in directives

    def test_env_var_redaction(self):
        env_vars = [
            "PATH=/usr/bin:/bin",
            "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
            "PRIVATE_KEY_PATH=/app/certs/priv.key",
            "TLS_KEY=super_secret_unencrypted_key_content_12345",
        ]

        obs = ConfigParser.inspect_env_variables(env_vars, target_id="container-1")
        assert len(obs) >= 2

        # Check values are strictly redacted
        for o in obs:
            presence = o.evidence.get("redacted_value_presence", "")
            assert "super_secret_unencrypted_key_content_12345" not in presence
            assert "redacted" in presence or "present" in presence


class TestPQCAndPackageDiscovery:
    """Test PQC recognition and static package parsing."""

    def test_pqc_algorithm_detection(self):
        text = "Configuring post-quantum key exchange using ML-KEM-768 and signatures with Dilithium3."
        obs = PQCDetector.inspect_text_content(text, filepath="config.yaml", target_id="target-pqc")
        assert len(obs) >= 2
        algos = {o.algorithm for o in obs}
        assert "ML-KEM" in algos
        assert "ML-DSA" in algos

    def test_pqc_library_package_evaluation(self):
        pkg = PackageObservation(
            ecosystem="dpkg",
            name="liboqs-dev",
            version="0.9.0",
            source_file="/var/lib/dpkg/status",
        )
        pqc_obs = PQCDetector.evaluate_package(pkg, target_id="pkg-1")
        assert pqc_obs is not None
        assert pqc_obs.pqc_classification == "PQC_CAPABLE_LIBRARY"

    def test_dpkg_status_parsing(self, tmp_path):
        dpkg_file = tmp_path / "status"
        dpkg_file.write_text(
            "Package: openssl\n"
            "Status: install ok installed\n"
            "Version: 3.0.2-0ubuntu1.15\n"
            "License: Apache-2.0\n"
            "\n"
            "Package: curl\n"
            "Status: install ok installed\n"
            "Version: 7.81.0\n"
            "\n"
        )

        pkgs = OSPackageParser.parse_dpkg_status(str(dpkg_file))
        assert len(pkgs) == 2
        names = {p.name: p for p in pkgs}
        assert "openssl" in names
        assert names["openssl"].version == "3.0.2-0ubuntu1.15"

        # Check crypto matching
        matched = CryptoLibraryMatcher.match_package(names["openssl"], target_id="dpkg-test")
        assert matched is not None
        assert "TLS" in matched.evidence.get("primitives", [])

    def test_static_binary_inspection(self, tmp_path):
        so_file = tmp_path / "libssl.so.3"
        # Dummy ELF with embedded OpenSSL version string
        so_file.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100 + b"OpenSSL 3.0.2 15 Mar 2022" + b"\x00" * 100)

        obs = BinaryInspector.inspect_binary(str(so_file))
        assert len(obs) >= 1
        algorithms = [o.algorithm for o in obs]
        assert any("OpenSSL" in a for a in algorithms)
