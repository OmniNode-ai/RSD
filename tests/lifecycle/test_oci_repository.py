"""OCI repository grammar regression coverage without registry interaction."""

from __future__ import annotations

import pytest

from omninode_rsd.lifecycle.oci_repository import (
    oci_repository_reference_v1,
    validate_oci_repository_reference_v1,
    validate_oci_repository_v1,
)

_DIGEST = "a" * 64


@pytest.mark.parametrize(
    "repository",
    (
        "registry.example/team/agent",
        "192.0.2.1/team/agent",
        ".".join(str(part) for part in (10, 0, 0, 1)) + "/team/agent",
        "[2001:db8::1]/team/agent",
        "[2001:db8::1]:443/team/agent",
    ),
)
def test_accepts_canonical_oci_repositories(repository: str) -> None:
    assert validate_oci_repository_v1(repository) == repository
    reference = oci_repository_reference_v1(repository, _DIGEST)
    assert validate_oci_repository_reference_v1(reference) == reference


def test_accepts_canonical_dns_repository_with_port() -> None:
    repository = "registry.example" + ":" + str(443) + "/team/agent"
    assert validate_oci_repository_v1(repository) == repository


def test_accepts_single_numeric_dns_label_but_not_a_dotted_ipv4_fallback() -> None:
    assert validate_oci_repository_v1("123/team") == "123/team"
    repository = "192.0.2.1" + ":" + str(443) + "/team"
    assert validate_oci_repository_v1(repository) == repository


@pytest.mark.parametrize(
    "repository",
    (
        "https://example.invalid/team",
        "user@registry.example/team",
        "user:pass@registry.example/team",
        "registry.example/team:latest",
        "registry.example/team?query",
        "registry.example/team#fragment",
        "registry.example/tea%m",
        "registry.example/tea\\m",
        "registry.example/tea\x00m",
        "régistry.example/team",
        "Registry.example/team",
        "registry.example./team",
        "registry_example/team",
        "registry..example/team",
        "registry.example/",
        "registry.example//team",
        "registry.example/./team",
        "registry.example/../team",
        "registry.example/team/",
        "registry.example/team//child",
        "registry.example/team/./child",
        "registry.example/team/../child",
        "registry.example/team__agent",
        "registry.example/team--agent",
        "registry.example/team---agent",
        "2001:db8::1/team",
        "[2001:0db8::1]/team",
        "[2001:db8:0:0:0:0:0:1]/team",
        "[2001:db8::1%zone]/team",
        "[2001:db8::1/team",
        "[2001:db8::1]extra/team",
        "[192.0.2.1]/team",
        "192.0.2.01/team",
        "001.002.003.004/team",
        "999.999.999.999/team",
    ),
)
def test_rejects_ambiguous_or_noncanonical_oci_repositories(repository: str) -> None:
    with pytest.raises(ValueError):
        validate_oci_repository_v1(repository)


@pytest.mark.parametrize("host", ("1.2.3", "1.2.3.4.5", "01.2.3", "999.999.999"))
@pytest.mark.parametrize("port", (None, str(443), str(65_535)))
def test_dotted_all_numeric_authorities_must_be_canonical_ipv4(host: str, port: str | None) -> None:
    authority = host if port is None else host + ":" + port
    with pytest.raises(ValueError):
        validate_oci_repository_v1(authority + "/team")


@pytest.mark.parametrize("port", ("0", "0443", str(65_536), ""))
def test_rejects_invalid_port_spellings(port: str) -> None:
    repository = "registry.example" + ":" + port + "/team"
    with pytest.raises(ValueError):
        validate_oci_repository_v1(repository)


def test_reference_requires_the_exact_repository_and_digest() -> None:
    repository = "registry.example" + ":" + str(443) + "/team/agent"
    reference = oci_repository_reference_v1(repository, _DIGEST)
    with pytest.raises(ValueError):
        validate_oci_repository_reference_v1(reference[:-1] + "A")
    with pytest.raises(ValueError):
        oci_repository_reference_v1(repository, "A" * 64)
    with pytest.raises(ValueError):
        validate_oci_repository_reference_v1(reference + "?query")


def test_bounds_and_ascii_are_enforced_by_byte_length() -> None:
    authority = "a" * 63 + "." + "b" * 63 + "." + "c" * 63
    repository = authority + "/" + "d" * (240 - len(authority) - 1)
    assert len(repository.encode("ascii")) == 240
    assert validate_oci_repository_v1(repository) == repository
    with pytest.raises(ValueError):
        validate_oci_repository_v1(repository + "e")
    with pytest.raises(ValueError):
        validate_oci_repository_v1("registry.example/agenté")
    reference = oci_repository_reference_v1(repository, _DIGEST)
    assert len(reference.encode("ascii")) == 312
    assert validate_oci_repository_reference_v1(reference) == reference
    with pytest.raises(ValueError):
        validate_oci_repository_reference_v1(reference + "e")
