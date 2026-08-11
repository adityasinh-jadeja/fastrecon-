"""
Tests for fastrecon.cloud_hunter — Cloud bucket detection with body verification.
Uses aioresponses to mock HTTP responses without real network calls.
"""

import asyncio
import json

import aiohttp
import pytest
from aioresponses import aioresponses

from fastrecon.cloud_hunter import (
    _check_bucket,
    _verify_public_body,
    generate_bucket_permutations,
)


# ── Tests for generate_bucket_permutations ──


class TestGenerateBucketPermutations:
    def test_basic_domain(self):
        perms = generate_bucket_permutations("example.com")
        assert "example" in perms
        assert "example-com" in perms
        assert "examplecom" in perms
        # Should have suffix variants
        assert "example-backup" in perms
        assert "example-dev" in perms

    def test_deduplication(self):
        perms = generate_bucket_permutations("test.com")
        assert len(perms) == len(set(perms))

    def test_length_constraints(self):
        """All permutations should be 3-63 chars."""
        perms = generate_bucket_permutations("a.b")
        for p in perms:
            assert 3 <= len(p) <= 63, f"Permutation '{p}' violates length constraint"


# ── Tests for _verify_public_body ──


class TestVerifyPublicBody:
    def test_s3_valid_listing(self):
        body = '<?xml version="1.0"?><ListBucketResult><Contents><Key>file.txt</Key></Contents></ListBucketResult>'
        assert _verify_public_body("AWS S3", body) is True

    def test_s3_generic_error_page(self):
        body = "<html><body>Welcome to our website</body></html>"
        assert _verify_public_body("AWS S3", body) is False

    def test_s3_empty_body(self):
        assert _verify_public_body("AWS S3", "") is False
        assert _verify_public_body("AWS S3", None) is False

    def test_gcs_valid_listing(self):
        body = json.dumps({"kind": "storage#objects", "items": [{"name": "file.txt"}]})
        assert _verify_public_body("GCP Storage", body) is True

    def test_gcs_error_page(self):
        body = "<html><body>Not Found</body></html>"
        assert _verify_public_body("GCP Storage", body) is False

    def test_gcs_invalid_json(self):
        body = "this is not json"
        assert _verify_public_body("GCP Storage", body) is False

    def test_azure_valid_listing(self):
        body = '<?xml version="1.0"?><EnumerationResults><Blobs><Blob><Name>file.txt</Name></Blob></Blobs></EnumerationResults>'
        assert _verify_public_body("Azure Blob", body) is True

    def test_azure_error_page(self):
        body = "<html>Error</html>"
        assert _verify_public_body("Azure Blob", body) is False

    def test_firebase_rtdb_public(self):
        body = '{"users": {"user1": {"name": "Alice"}}}'
        assert _verify_public_body("Firebase RTDB", body) is True

    def test_firebase_rtdb_null_is_public(self):
        """Even 'null' means the DB is publicly accessible."""
        assert _verify_public_body("Firebase RTDB", "null") is True

    def test_firebase_rtdb_permission_denied(self):
        body = '{"error": "Permission Denied"}'
        assert _verify_public_body("Firebase RTDB", body) is False

    def test_firebase_storage_valid(self):
        body = json.dumps({"items": [{"name": "file.jpg"}]})
        assert _verify_public_body("Firebase Storage", body) is True

    def test_firebase_storage_error(self):
        body = json.dumps({"error": {"code": 404}})
        assert _verify_public_body("Firebase Storage", body) is False

    def test_unknown_provider(self):
        """Unknown providers should default to False (conservative)."""
        assert _verify_public_body("UnknownCloud", "anything") is False


# ── Tests for _check_bucket with mocked HTTP ──


class TestCheckBucket:
    @pytest.mark.asyncio
    async def test_s3_public_with_valid_listing(self):
        """S3 200 with ListBucketResult XML = PUBLIC."""
        url = "https://example.s3.amazonaws.com/"
        body = '<?xml version="1.0"?><ListBucketResult><Contents><Key>file.txt</Key></Contents></ListBucketResult>'

        with aioresponses() as mocked:
            mocked.get(url, status=200, body=body)
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                result, alert = await _check_bucket(
                    session, "AWS S3", "https://{bucket}.s3.amazonaws.com/",
                    "example", sem
                )
                assert result is not None
                assert result["status"] == "PUBLIC"
                assert alert is not None
                assert alert["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_s3_200_generic_page_not_public(self):
        """S3 200 with generic HTML page = UNVERIFIED (not PUBLIC)."""
        url = "https://example.s3.amazonaws.com/"
        body = "<html><body>Some generic page</body></html>"

        with aioresponses() as mocked:
            mocked.get(url, status=200, body=body)
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                result, alert = await _check_bucket(
                    session, "AWS S3", "https://{bucket}.s3.amazonaws.com/",
                    "example", sem
                )
                assert result is not None
                assert result["status"] == "UNVERIFIED"
                assert alert is None  # No alert for unverified

    @pytest.mark.asyncio
    async def test_s3_403_is_private(self):
        """S3 403 = PRIVATE, no alert."""
        url = "https://example.s3.amazonaws.com/"

        with aioresponses() as mocked:
            mocked.get(url, status=403)
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                result, alert = await _check_bucket(
                    session, "AWS S3", "https://{bucket}.s3.amazonaws.com/",
                    "example", sem
                )
                assert result is not None
                assert result["status"] == "PRIVATE"
                assert alert is None

    @pytest.mark.asyncio
    async def test_s3_404_returns_none(self):
        """S3 404 = bucket doesn't exist, returns None."""
        url = "https://example.s3.amazonaws.com/"

        with aioresponses() as mocked:
            mocked.get(url, status=404)
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                result, alert = await _check_bucket(
                    session, "AWS S3", "https://{bucket}.s3.amazonaws.com/",
                    "example", sem
                )
                assert result is None
                assert alert is None

    @pytest.mark.asyncio
    async def test_gcs_public_with_valid_json(self):
        """GCS 200 with valid JSON listing = PUBLIC."""
        url = "https://storage.googleapis.com/example/"
        body = json.dumps({"kind": "storage#objects", "items": [{"name": "file.txt"}]})

        with aioresponses() as mocked:
            mocked.get(url, status=200, body=body)
            async with aiohttp.ClientSession() as session:
                sem = asyncio.Semaphore(10)
                result, alert = await _check_bucket(
                    session, "GCP Storage", "https://storage.googleapis.com/{bucket}/",
                    "example", sem
                )
                assert result is not None
                assert result["status"] == "PUBLIC"
                assert alert is not None
