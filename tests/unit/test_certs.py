import json
import os
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
from cryptography.x509.verification import VerificationError

from volttron.utils.certs import Certs, CertError
from volttron.utils.context import ClientContext



@pytest.fixture
def certs_env(tmp_path, monkeypatch):
    instance_name = f"pytest-{int(time.time() * 1000)}"
    volttron_home = tmp_path / f"{instance_name}-home"
    volttron_home.mkdir()

    monkeypatch.setenv("VOLTTRON_HOME", str(volttron_home))
    ClientContext.__volttron_home__ = None  # reset cached home

    certs_dir = tmp_path / f"{instance_name}-certs"
    certs = Certs(certificate_dir=str(certs_dir))

    subject = {
        "C": "US",
        "ST": "Washington",
        "L": "Issaquah",
        "O": "Pytest Org",
        "OU": "Pytest Unit",
        "CN": f"{instance_name} root ca",
    }

    certs.create_root_ca(**subject)
    return certs, instance_name, certs_dir


def _bundle_trusted_cas(certs, *cert_names):
    bundle_path = Path(certs.cert_file(certs.trusted_ca_name))
    with open(bundle_path, "wb") as fp:
        for name in cert_names:
            fp.write(certs.cert(name, public_bytes=True))
    return bundle_path


def test_create_root_ca_and_load(certs_env):
    certs, instance_name, _ = certs_env

    assert certs.ca_exists() is True
    root = certs.ca_cert()
    assert root.subject == root.issuer

    bc = root.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    assert bc.ca is True


def test_create_intermediate_and_server_and_verify_hostname(certs_env):
    certs, instance_name, _ = certs_env

    intermediate_name = f"{instance_name}-intermediate"
    server_name = f"{instance_name}-server"
    hostname = "server.local"
    fqdn = "server.local"

    inter_cert, inter_key = certs.create_signed_cert_files(
        name=intermediate_name,
        cert_type="CA",
        overwrite=True,
    )
    assert inter_cert is not None
    assert inter_key is not None

    server_cert, server_key = certs.create_signed_cert_files(
        name=server_name,
        cert_type="server",
        ca_name=intermediate_name,
        overwrite=True,
        fqdn=fqdn,
    )
    assert server_cert is not None
    assert server_key is not None

    _bundle_trusted_cas(certs, certs.root_ca_name, intermediate_name)

    assert certs.verify_cert(server_name, hostname=hostname) is True


def test_verify_cert_wrong_hostname_raises(certs_env):
    certs, instance_name, _ = certs_env

    intermediate_name = f"{instance_name}-intermediate"
    server_name = f"{instance_name}-server"

    certs.create_signed_cert_files(
        name=intermediate_name,
        cert_type="CA",
        overwrite=True,
    )

    certs.create_signed_cert_files(
        name=server_name,
        cert_type="server",
        ca_name=intermediate_name,
        overwrite=True,
        fqdn="server.local",
    )

    _bundle_trusted_cas(certs, certs.root_ca_name, intermediate_name)

    with pytest.raises(VerificationError):
        certs.verify_cert(server_name, hostname="wrong.example")


def test_verify_cert_without_hostname_returns_true_for_valid_chain(certs_env):
    certs, instance_name, _ = certs_env

    intermediate_name = f"{instance_name}-intermediate"
    client_name = f"{instance_name}-client"

    certs.create_signed_cert_files(
        name=intermediate_name,
        cert_type="CA",
        overwrite=True,
    )

    certs.create_signed_cert_files(
        name=client_name,
        cert_type="client",
        ca_name=intermediate_name,
        overwrite=True,
    )

    _bundle_trusted_cas(certs, certs.root_ca_name, intermediate_name)

    assert certs.verify_cert(client_name) is True


def test_verify_client_cert_returns_true_for_valid_client_chain(certs_env):
    certs, instance_name, _ = certs_env

    intermediate_name = f"{instance_name}-intermediate"
    client_name = f"{instance_name}-client"

    certs.create_signed_cert_files(
        name=intermediate_name,
        cert_type="CA",
        overwrite=True,
    )

    client_cert, _ = certs.create_signed_cert_files(
        name=client_name,
        cert_type="client",
        ca_name=intermediate_name,
        overwrite=True,
    )

    eku = client_cert.extensions.get_extension_for_oid(
        ExtensionOID.EXTENDED_KEY_USAGE
    ).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku

    _bundle_trusted_cas(certs, certs.root_ca_name, intermediate_name)

    assert certs.verify_client_cert(client_name) is True


def test_server_cert_has_san_and_server_auth(certs_env):
    certs, instance_name, _ = certs_env

    intermediate_name = f"{instance_name}-intermediate"
    server_name = f"{instance_name}-server"

    certs.create_signed_cert_files(
        name=intermediate_name,
        cert_type="CA",
        overwrite=True,
    )

    server_cert, _ = certs.create_signed_cert_files(
        name=server_name,
        cert_type="server",
        ca_name=intermediate_name,
        overwrite=True,
        fqdn="server.local",
    )

    san = server_cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value
    dns_names = san.get_values_for_type(x509.DNSName)
    assert "server.local" in dns_names

    eku = server_cert.extensions.get_extension_for_oid(
        ExtensionOID.EXTENDED_KEY_USAGE
    ).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku


def test_verify_cert_raises_for_missing_cert(certs_env):
    certs, _, _ = certs_env

    with pytest.raises(CertError):
        certs.verify_cert("does-not-exist")


# ---------------------------------------------------------------------------
# Pending CSR files are named after the CSR's common name, which the remote
# peer chooses (CERT VU#173170.1, claims 8 and 9).

@pytest.mark.parametrize("name", [
    "volttron1.platform.agent", "v1.federation", "a-b_c.d", "x", "A" * 255,
])
def test_validate_csr_common_name_accepts_identities(name):
    from volttron.utils.certs import validate_csr_common_name
    assert validate_csr_common_name(name) == name


@pytest.mark.parametrize("name", [
    "../volttron1.agent", "volttron1.agent/../../web-users", "volttron1./agent", "/etc/passwd",
    "volttron1.agent\x00", ".hidden", "..", ".", "", " volttron1.agent", "volttron1.agent\n",
    "volttron1.agent;rm", "A" * 256, None, 5, b"volttron1.agent",
])
def test_validate_csr_common_name_refuses_paths_and_odd_input(name):
    from volttron.utils.certs import validate_csr_common_name
    with pytest.raises(ValueError) as excinfo:
        validate_csr_common_name(name)
    # The attacker-supplied name is not echoed.
    assert str(name) not in str(excinfo.value) or name in ("", None, 5)


FAKE_CSR = b"-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n"


def test_save_pending_csr_request_refuses_traversal_and_writes_nothing(certs_env):
    certs, instance_name, certs_dir = certs_env
    before = set(os.listdir(certs.csr_pending_dir))
    for bad in ("../escaped", f"{instance_name}.agent/../../web-users", f"{instance_name}.agent\n"):
        with pytest.raises(ValueError):
            certs.save_pending_csr_request("10.0.0.1", bad, FAKE_CSR)
    assert set(os.listdir(certs.csr_pending_dir)) == before
    assert not (Path(certs.csr_pending_dir).parent / "escaped.json").exists()


def test_save_pending_csr_request_records_once_and_never_overwrites(certs_env):
    certs, instance_name, certs_dir = certs_env
    name = f"{instance_name}.remote.agent"
    csrfile = certs.save_pending_csr_request("10.0.0.1", name, FAKE_CSR)
    metafile = Path(certs.csr_pending_dir) / (name + ".json")
    assert csrfile == os.path.join(certs.csr_pending_dir, name + ".csr")
    assert Path(csrfile).read_bytes() == FAKE_CSR
    assert [req["identity"] for req in certs.get_pending_csr_requests()] == [name]

    # A second request for the same name changes nothing.
    certs.save_pending_csr_request("10.0.0.2", name, b"other")
    assert Path(csrfile).read_bytes() == FAKE_CSR
    assert json.loads(metafile.read_text())["remote_ip_address"] == "10.0.0.1"

    # Nor does a request for a name whose .csr exists without its .json (claim 9).
    metafile.unlink()
    certs.save_pending_csr_request("10.0.0.2", name, b"other")
    assert Path(csrfile).read_bytes() == FAKE_CSR
    assert not metafile.exists()
