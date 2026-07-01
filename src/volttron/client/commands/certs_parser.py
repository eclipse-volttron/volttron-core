import sys
import os

from volttron.utils.certs import Certs


def prompt_response(prompt, default=None, mandatory=False):
    """
    Prompt the user for input with optional default and mandatory validation.

    :param prompt: The prompt text to display
    :param default: Optional default value if user presses enter
    :param mandatory: If True, keep prompting until user provides input
    :return: User's response or default value
    """
    while True:
        if default:
            display_prompt = f"{prompt} [{default}]: "
        else:
            display_prompt = f"{prompt}: "

        response = input(display_prompt).strip()

        if response:
            return response
        elif default:
            return default
        elif mandatory:
            print("  This field is mandatory. Please provide a value.")
            continue
        else:
            return ""


def create_cert(opts):
    """Handler for creating certificates."""
    from typing import Dict

    certs_instance = Certs()
    # For CA certs, default name to root_ca_name if not provided
    if opts.type == "root-ca":
        if opts.name:
            print("Root CA for a VOLTTRON instance will always be created using instance name")
        opts.name = certs_instance.root_ca_name
    # name is required
    if not opts.name:
        print(
            "Error: certificate name is required",
            file=sys.stderr,
        )
        sys.exit(1)

    cert_already_exists = certs_instance.cert_exists(opts.name)

    # If cert already existed and overwrite=False, it just returns the existing cert
    if cert_already_exists and not opts.overwrite:
        print(f"{opts.type} certificate already exists: {opts.name}")
        print("Use --overwrite to replace the existing certificate")
        return


    if opts.type == "root-ca":
        # Prompt for CA certificate details
        cert_data: Dict[str, str] = {}

        print("\nEnter certificate subject details (mandatory fields required):")
        cert_data["C"] = prompt_response("\tCountry", default="US")
        cert_data["ST"] = prompt_response("\tState", mandatory=True)
        cert_data["L"] = prompt_response("\tLocation (City)", mandatory=True)
        cert_data["O"] = prompt_response("\tOrganization", mandatory=True)
        cert_data["OU"] = prompt_response("\tOrganization Unit", mandatory=False)

        # Common name for CA is typically set by the library, but can be overridden
        cn_prompt = "\tCommon Name (leave empty for default instance name)"
        cn_value = prompt_response(cn_prompt, default=None, mandatory=False)
        if cn_value:  # Only include if user provided a value
            cert_data["CN"] = cn_value

        try:
            result = certs_instance.create_root_ca(
                overwrite=opts.overwrite,
                valid_days=opts.valid_days,
                **cert_data,  # type: ignore[misc]
            )

            # create_root_ca returns None if CA already exists and overwrite=False
            if result is None:
                print(f"Root CA certificate already exists: {certs_instance.root_ca_name}")
                print("Use --overwrite to replace the existing certificate")
                return

            cert, key = result
            print(f"Successfully created root CA certificate: {certs_instance.root_ca_name}")

            # Ask if user wants to add this CA to trusted CAs
            add_to_trusted = (
                input(
                    f"\nAdd this CA to trusted CAs? Type 'y' or 'yes' to confirm: "
                )
                .strip()
                .lower()
            )
            if add_to_trusted in ('yes', 'y'):
                try:
                    from shutil import copyfile
                    src = certs_instance.cert_file(certs_instance.root_ca_name)
                    dst = certs_instance.cert_file(certs_instance.trusted_ca_name)
                    copyfile(src, dst)
                    print(f"Added {certs_instance.root_ca_name} to trusted CAs")
                except Exception as e:
                    print(f"Warning: Failed to add CA to trusted CAs: {e}", file=sys.stderr)
        except Exception as e:
            print(f"Error creating CA certificate: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            if opts.ca_name:
                if not certs_instance.cert_exists(opts.ca_name):
                    print(
                        f"Error creating certificate: CA file {certs_instance.cert_file(opts.ca_name)} doesn't exists",
                        file=sys.stderr,
                    )
                    sys.exit(1)
            else:
                # check if root ca exists if so use that to sign
                if not certs_instance.ca_exists():
                    print(
                        f"Error creating certificate:No CA file found. Create self signed root CA certificate using --type root-ca or provide existing ca cert using --ca_name",
                        file=sys.stderr,
                    )
                    sys.exit(1)

            if opts.type == 'ca':
                opts.type = "CA"
            cert, key = certs_instance.create_signed_cert_files(
                name=opts.name,
                cert_type=opts.type,
                ca_name=opts.ca_name,
                overwrite=opts.overwrite,
                valid_days=opts.valid_days,
                fqdn=opts.fqdn if hasattr(opts, "fqdn") else None,
            )

            print(f"Successfully created {opts.type} certificate: {opts.name}")
        except Exception as e:
            print(f"Error creating certificate: {e}", file=sys.stderr)
            sys.exit(1)


def list_certs(opts):
    """Handler for listing certificates."""
    try:
        certs_instance = Certs()

        # List certificate files in the cert directory
        if not os.path.exists(certs_instance.cert_dir):
            print("No certificates found.")
            return

        cert_files = [
            f[:-4] for f in os.listdir(certs_instance.cert_dir) if f.endswith(".crt")
        ]

        if not cert_files:
            print("No certificates found.")
            return

        print("\nAvailable certificates:")
        for cert_name in sorted(cert_files):
            if opts.details:
                try:
                    subject = certs_instance.get_cert_subject(cert_name)
                    print(f"\n  {cert_name}:")
                    print(f"    Common Name: {subject['common-name']}")
                    print(f"    Country: {subject['country']}")
                    print(f"    State: {subject['state']}")
                    print(f"    Location: {subject['location']}")
                    print(f"    Organization: {subject['organization']}")
                    print(f"    Organization Unit: {subject['organization-unit']}")
                except Exception as e:
                    print(f"\n  {cert_name}: (error reading details: {e})")
            else:
                print(f"  - {cert_name}")
    except Exception as e:
        print(f"Error listing certificates: {e}", file=sys.stderr)
        sys.exit(1)


def remove_cert(opts):
    """Handler for removing certificates."""
    try:
        certs_instance = Certs()

        if not certs_instance.cert_exists(opts.name, remote=False):
            print(f"Certificate '{opts.name}' not found.", file=sys.stderr)
            sys.exit(1)

        # Prompt for confirmation (require explicit yes/y to proceed)
        confirm = (
            input(
                f"Are you sure you want to remove certificate '{opts.name}'? Type 'y' or 'yes' to confirm: "
            )
            .strip()
            .lower()
        )
        if confirm not in ('yes', 'y'):
            print("Removal cancelled.")
            return

        certs_instance.delete_cert(opts.name)
        print(f"Successfully removed certificate: {opts.name}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error removing certificate: {e}", file=sys.stderr)
        sys.exit(1)


def add_cert_parser(add_parser_fn):
    """Create and populate the argparse parser for certificate commands."""
    cert_cmds = add_parser_fn("cert", help="create, list, or remove certificates")
    cert_subparsers = cert_cmds.add_subparsers(
        title="subcommands",
        metavar="",
        dest="store_commands",
    )

    cert_create = add_parser_fn(
        "create",
        help="create a new certificate",
        subparser=cert_subparsers,
    )
    cert_create.add_argument(
        "--type",
        choices=("client", "server", "root-ca", "ca"),
        default="client",
        help="certificate type",
    )
    cert_create.add_argument(
        "--ca-name",
        dest="ca_name",
        default=None,
        help="certificate authority used to sign the new certificate",
    )
    cert_create.add_argument(
        "--valid-days",
        dest="valid_days",
        type=int,
        default=3650,
        help="number of days the certificate should be valid",
    )
    cert_create.add_argument(
        "--overwrite",
        action="store_true",
        help="overwrite existing certificate files",
    )
    cert_create.add_argument(
        "--fqdn",
        help="fully qualified domain name to use for server certificates",
    )
    cert_create.add_argument(
        "name",
        nargs="?",
        default=None,
        help="name used for the certificate files (ignored for root-ca cert, defaults to instance root CA)",
    )
    cert_create.set_defaults(func=create_cert)

    ####
    cert_list = add_parser_fn(
        "list",
        help="list certificates",
        subparser=cert_subparsers,
    )
    # cert_list.add_argument(
    #     "--remote",
    #     action="store_true",
    #     help="list remote certificates instead of local certificates",
    # )
    cert_list.add_argument(
        "--details",
        action="store_true",
        help="show certificate subject details",
    )
    cert_list.set_defaults(func=list_certs)

    ####
    cert_remove = add_parser_fn(
        "remove",
        help="remove a certificate",
        subparser=cert_subparsers,
    )
    cert_remove.add_argument("name", help="name of the certificate to remove")
    # cert_remove.add_argument(
    #     "--remote",
    #     action="store_true",
    #     help="remove a remote certificate instead of a local certificate",
    # )
    cert_remove.set_defaults(func=remove_cert)
