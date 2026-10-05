"""
QuantumShield — Container & Filesystem Inspection Engine Tests
Tests:
  - Recursive traversal & depth limits
  - Scope enforcement & symlink escape defense
  - Special file isolation
  - Archive security & path traversal rejection
  - OCI/Docker layer reconstruction & whiteout handling (.wh.<file>, .wh..wh..opq)
  - Layer provenance tracking (layer_introduced, layer_deleted, final_image_presence)
"""

import io
import os
import tarfile
import tempfile
import pytest

from app.scanner.container.container.archive import SafeArchiveExtractor, ArchiveSecurityError
from app.scanner.container.container.layer_reconstructor import LayerReconstructor
from app.scanner.container.filesystem.classifier import FileClassifier
from app.scanner.container.filesystem.traversal import SafeFilesystemWalker
from app.scanner.container.models import ContainerLayer, ResourceLimits


class TestFilesystemTraversal:
    """Test safe, bounded filesystem traversal."""

    def test_recursive_traversal_and_classification(self, tmp_path):
        # Create test directory structure
        sub = tmp_path / "sub" / "inner"
        sub.mkdir(parents=True)

        cert_file = sub / "test.crt"
        cert_file.write_text("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----")

        conf_file = sub / "nginx.conf"
        conf_file.write_text("ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL;")

        walker = SafeFilesystemWalker(authorized_root=str(tmp_path))
        artifacts = walker.walk()

        rel_paths = {a.relative_path.replace("\\", "/") for a in artifacts}
        assert "sub/inner/test.crt" in rel_paths
        assert "sub/inner/nginx.conf" in rel_paths
        assert walker.files_inspected == 2

    def test_depth_limit_enforcement(self, tmp_path):
        # Create deep directory hierarchy
        curr = tmp_path
        for i in range(10):
            curr = curr / f"depth_{i}"
            curr.mkdir()
        (curr / "deep_file.txt").write_text("deep")

        # Set max_directory_depth = 4
        limits = ResourceLimits(max_directory_depth=4)
        walker = SafeFilesystemWalker(authorized_root=str(tmp_path), limits=limits)
        artifacts = walker.walk()

        # Deep file should be skipped due to depth limit
        assert not any("deep_file.txt" in a.relative_path for a in artifacts)
        assert any("DEPTH_LIMIT_REACHED" in evt for evt in walker.events)

    def test_file_count_limit(self, tmp_path):
        for i in range(15):
            (tmp_path / f"file_{i}.txt").write_text("content")

        limits = ResourceLimits(max_file_count=5)
        walker = SafeFilesystemWalker(authorized_root=str(tmp_path), limits=limits)
        artifacts = walker.walk()

        assert len(artifacts) <= 5
        assert any("RESOURCE_LIMIT_EXCEEDED" in evt for evt in walker.events)

    def test_scope_subscope_violation(self, tmp_path):
        walker = SafeFilesystemWalker(authorized_root=str(tmp_path))
        artifacts = walker.walk(sub_scope="../../outside")
        assert artifacts == []
        assert any("SCOPE_VIOLATION" in evt for evt in walker.events)

    def test_file_classifier_magic(self, tmp_path):
        jks = tmp_path / "keystore.bin"
        jks.write_bytes(b"\xfe\xed\xfe\xed\x00\x00\x00\x02")

        ftype, meta = FileClassifier.classify(str(jks), len(b"\xfe\xed\xfe\xed\x00\x00\x00\x02"))
        assert ftype == "keystore"
        assert meta.get("keystore_format") == "JKS"

        elf = tmp_path / "app.bin"
        elf.write_bytes(b"\x7fELF\x02\x01\x01\x00")
        ftype_elf, meta_elf = FileClassifier.classify(str(elf), 8)
        assert ftype_elf == "binary"
        assert meta_elf.get("format") == "ELF"


class TestArchiveSecurity:
    """Test defense against malicious archives and path traversal."""

    def test_path_traversal_rejection(self, tmp_path):
        tar_path = tmp_path / "traversal.tar"
        with tarfile.open(tar_path, "w") as tar:
            # Add a normal file
            ti_good = tarfile.TarInfo("safe.txt")
            ti_good.size = 4
            tar.addfile(ti_good, io.BytesIO(b"safe"))

            # Add a traversal member: ../evil.txt
            ti_evil = tarfile.TarInfo("../evil.txt")
            ti_evil.size = 4
            tar.addfile(ti_evil, io.BytesIO(b"evil"))

        dest_dir = tmp_path / "extracted"
        dest_dir.mkdir()

        extractor = SafeArchiveExtractor()
        extracted = extractor.safe_extract_tar(str(tar_path), str(dest_dir))

        # safe.txt must be extracted, evil.txt must be rejected
        assert os.path.exists(dest_dir / "safe.txt")
        assert not os.path.exists(tmp_path / "evil.txt")
        assert any("PATH_TRAVERSAL_REJECTED" in evt for evt in extractor.events)

    def test_symlink_escape_rejection(self, tmp_path):
        tar_path = tmp_path / "symlink_escape.tar"
        with tarfile.open(tar_path, "w") as tar:
            ti_sym = tarfile.TarInfo("link_to_etc")
            ti_sym.type = tarfile.SYMTYPE
            ti_sym.linkname = "/etc/passwd"
            tar.addfile(ti_sym)

        dest_dir = tmp_path / "extracted_sym"
        dest_dir.mkdir()

        extractor = SafeArchiveExtractor()
        extractor.safe_extract_tar(str(tar_path), str(dest_dir))
        assert any("SYMLINK_ESCAPE_REJECTED" in evt for evt in extractor.events)

    def test_archive_max_file_count_limit(self, tmp_path):
        tar_path = tmp_path / "bomb.tar"
        with tarfile.open(tar_path, "w") as tar:
            for i in range(20):
                ti = tarfile.TarInfo(f"file_{i}.txt")
                ti.size = 1
                tar.addfile(ti, io.BytesIO(b"a"))

        dest_dir = tmp_path / "extracted_bomb"
        dest_dir.mkdir()

        limits = ResourceLimits(max_file_count=5)
        extractor = SafeArchiveExtractor(limits=limits)
        with pytest.raises(ArchiveSecurityError):
            extractor.safe_extract_tar(str(tar_path), str(dest_dir))


class TestLayerReconstructionAndWhiteouts:
    """Test sequential layer merger and standard/opaque whiteouts."""

    def test_standard_whiteout_deletion_marker(self, tmp_path):
        """
        Prompt requirement 12 test:
          Layer 1: /etc/old.key
          Layer 2: deletion marker for /etc/old.key (.wh.old.key)
          Final merged view: /etc/old.key is absent!
        """
        layer1_tar = tmp_path / "layer1.tar"
        with tarfile.open(layer1_tar, "w") as tar:
            ti = tarfile.TarInfo("etc/old.key")
            content = b"-----BEGIN PRIVATE KEY-----\nMIG...\n-----END PRIVATE KEY-----"
            ti.size = len(content)
            tar.addfile(ti, io.BytesIO(content))

            ti_keep = tarfile.TarInfo("etc/server.crt")
            c_keep = b"-----BEGIN CERTIFICATE-----\nKEEP\n-----END CERTIFICATE-----"
            ti_keep.size = len(c_keep)
            tar.addfile(ti_keep, io.BytesIO(c_keep))

        layer2_tar = tmp_path / "layer2.tar"
        with tarfile.open(layer2_tar, "w") as tar:
            # Whiteout marker: etc/.wh.old.key
            ti_wh = tarfile.TarInfo("etc/.wh.old.key")
            ti_wh.size = 0
            tar.addfile(ti_wh, io.BytesIO(b""))

            # New file in layer 2
            ti_new = tarfile.TarInfo("etc/new.key")
            c_new = b"-----BEGIN PRIVATE KEY-----\nNEW\n-----END PRIVATE KEY-----"
            ti_new.size = len(c_new)
            tar.addfile(ti_new, io.BytesIO(c_new))

        layers = [
            ContainerLayer(layer_index=0, layer_digest="sha256:layer1", layer_tar_path=str(layer1_tar)),
            ContainerLayer(layer_index=1, layer_digest="sha256:layer2", layer_tar_path=str(layer2_tar)),
        ]

        merged_dest = tmp_path / "merged_fs"
        reconstructor = LayerReconstructor()
        recon_result = reconstructor.reconstruct_layers(layers, str(merged_dest))

        # Check final filesystem
        assert not os.path.exists(merged_dest / "etc" / "old.key"), "Whiteout failed: old.key should NOT exist in merged view"
        assert os.path.exists(merged_dest / "etc" / "server.crt"), "server.crt should remain present"
        assert os.path.exists(merged_dest / "etc" / "new.key"), "new.key should be present"

        # Check provenance
        old_key_prov = recon_result.provenance.get("etc/old.key")
        assert old_key_prov is not None
        assert old_key_prov.final_image_presence is False
        assert old_key_prov.historical_layer_presence is True
        assert old_key_prov.layer_introduced == 0
        assert old_key_prov.layer_deleted == 1

        new_key_prov = recon_result.provenance.get("etc/new.key")
        assert new_key_prov is not None
        assert new_key_prov.final_image_presence is True
        assert new_key_prov.layer_introduced == 1

    def test_opaque_whiteout(self, tmp_path):
        """Test .wh..wh..opq masks all lower files in directory."""
        layer1_tar = tmp_path / "layer1.tar"
        with tarfile.open(layer1_tar, "w") as tar:
            for f in ("app/secret1.pem", "app/secret2.pem"):
                ti = tarfile.TarInfo(f)
                ti.size = 5
                tar.addfile(ti, io.BytesIO(b"hello"))

        layer2_tar = tmp_path / "layer2.tar"
        with tarfile.open(layer2_tar, "w") as tar:
            # Opaque whiteout inside app/
            ti_opq = tarfile.TarInfo("app/.wh..wh..opq")
            ti_opq.size = 0
            tar.addfile(ti_opq, io.BytesIO(b""))

            # Only secret3 added in layer 2
            ti_new = tarfile.TarInfo("app/secret3.pem")
            ti_new.size = 5
            tar.addfile(ti_new, io.BytesIO(b"world"))

        layers = [
            ContainerLayer(layer_index=0, layer_digest="sha256:layer1", layer_tar_path=str(layer1_tar)),
            ContainerLayer(layer_index=1, layer_digest="sha256:layer2", layer_tar_path=str(layer2_tar)),
        ]

        merged_dest = tmp_path / "merged_opaque"
        reconstructor = LayerReconstructor()
        recon_result = reconstructor.reconstruct_layers(layers, str(merged_dest))

        assert not os.path.exists(merged_dest / "app" / "secret1.pem")
        assert not os.path.exists(merged_dest / "app" / "secret2.pem")
        assert os.path.exists(merged_dest / "app" / "secret3.pem")

        prov1 = recon_result.provenance.get("app/secret1.pem")
        assert prov1.final_image_presence is False
        assert prov1.layer_deleted == 1
