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
