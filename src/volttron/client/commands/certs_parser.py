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


def format_expiry(value):
    """Format certificate expiry value for CLI output."""
    if value is None:
        return "-"
    try:
        return value.strftime("%Y-%m-%d")
    except Exception:
        return str(value)


def create_cert(opts):
    """Handler for creating certificates."""
    certs_instance = Certs()
    # for root ca default name to certs_instance.root_ca_name if not provided
    if opts.type == "root-ca":
        if opts.ca_name:
            print("Error: --ca-name cannot be used with --type root-ca", file=sys.stderr)
            sys.exit(1)
        if opts.fqdn:
            print("Error: --fqdn can only be used with --type server", file=sys.stderr)
            sys.exit(1)
        if opts.name:
            print("Root CA for a VOLTTRON instance will always be created using instance name")
        opts.name = certs_instance.root_ca_name

    elif opts.type != "server" and opts.fqdn:
        print("Error: --fqdn can only be used with --type server", file=sys.stderr)
        sys.exit(1)

    if not opts.name:
        print("Error: certificate name is required", file=sys.stderr)
        sys.exit(1)

    cert_already_exists = certs_instance.cert_exists(opts.name)

    if cert_already_exists and not opts.overwrite:
        print(f"{opts.type} certificate already exists: {opts.name}")
        print("Use --overwrite to replace the existing certificate")
        return

    if opts.type == "root-ca":
        # Prompt for CA certificate details
        cert_data = {}
        print("\nEnter certificate subject details (mandatory fields required):")
        cert_data["C"] = prompt_response("\tCountry", default="US")
        cert_data["ST"] = prompt_response("\tState", mandatory=True)
        cert_data["L"] = prompt_response("\tLocation (City)", mandatory=True)
        cert_data["O"] = prompt_response("\tOrganization", mandatory=True)
        cert_data["OU"] = prompt_response("\tOrganization Unit", mandatory=False)
        cn_value = prompt_response(
            "\tCommon Name (leave empty for default instance name)",
            default=None,
            mandatory=False,
        )
        if cn_value:
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
                        f"Error creating certificate: CA file {certs_instance.cert_file(opts.ca_name)} doesn't exist",
                        file=sys.stderr,
                    )
                    sys.exit(1)
            elif not certs_instance.ca_exists():
                print(
                    "Error creating certificate: no CA file found. "
                    "Create a root CA with --type root-ca or provide --ca-name",
                    file=sys.stderr,
                )
                sys.exit(1)

            cert_type = "CA" if opts.type == "ca" else opts.type
            certs_instance.create_signed_cert_files(
                name=opts.name,
                cert_type=cert_type,
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

        cert_files = sorted(cert_files)

        if not opts.details:
            print("\nAvailable certificates:")
            for cert_name in cert_files:
                print(f"  - {cert_name}")
            return

        summaries = []
        for cert_name in cert_files:
            try:
                summaries.append(certs_instance.get_cert_summary(cert_name))
            except Exception as e:
                summaries.append(
                    {
                        "name": cert_name,
                        "type": "error",
                        "cn": "-",
                        "issuer_cn": str(e),
                        "expiry": None,
                    }
                )

        name_width = max(len("NAME"), max(len(item["name"]) for item in summaries))
        type_width = max(len("TYPE"), max(len(str(item.get("type") or "-")) for item in summaries))
        cn_width = max(len("CN"), max(len(str(item.get("cn") or "-")) for item in summaries))
        issuer_width = max(
            len("ISSUER"),
            max(len(str(item.get("issuer_cn") or "-")) for item in summaries),
        )

        print()
        header = (
            f"{'NAME'.ljust(name_width)}  "
            f"{'TYPE'.ljust(type_width)}  "
            f"{'CN'.ljust(cn_width)}  "
            f"{'ISSUER'.ljust(issuer_width)}  "
            f"EXPIRY"
        )
        print(header)
        print("-" * len(header))

        for item in summaries:
            print(
                f"{item['name'].ljust(name_width)}  "
                f"{str(item.get('type') or '-').ljust(type_width)}  "
                f"{str(item.get('cn') or '-').ljust(cn_width)}  "
                f"{str(item.get('issuer_cn') or '-').ljust(issuer_width)}  "
                f"{format_expiry(item.get('expiry'))}"
            )
    except Exception as e:
        print(f"Error listing certificates: {e}", file=sys.stderr)
        sys.exit(1)


def show_cert(opts):
    """Handler for showing details of a single certificate."""
    try:
        certs_instance = Certs()

        if not certs_instance.cert_exists(opts.name, remote=False):
            print(f"Certificate '{opts.name}' not found.", file=sys.stderr)
            sys.exit(1)

        summary = certs_instance.get_cert_summary(opts.name)
        subject = certs_instance.get_cert_subject(opts.name)
        cert = certs_instance.cert(opts.name)

        print(f"\nCertificate: {opts.name}")
        print(f"Type: {summary.get('type') or '-'}")
        print(f"Common Name: {summary.get('cn') or '-'}")
        print(f"Issuer: {summary.get('issuer_cn') or '-'}")
        print(f"Expiry: {format_expiry(summary.get('expiry'))}")
        print(f"Not Before: {cert.not_valid_before_utc}")
        print(f"Not After: {cert.not_valid_after_utc}")
        print(f"Serial Number: {cert.serial_number}")
        print(f"Country: {subject['country']}")
        print(f"State: {subject['state']}")
        print(f"Location: {subject['location']}")
        print(f"Organization: {subject['organization']}")
        print(f"Organization Unit: {subject['organization-unit']}")
    except Exception as e:
        print(f"Error showing certificate: {e}", file=sys.stderr)
        sys.exit(1)


def remove_cert(opts):
    """Handler for removing certificates."""
    try:
        certs_instance = Certs()

        if not certs_instance.cert_exists(opts.name, remote=False):
            print(f"Certificate '{opts.name}' not found.", file=sys.stderr)
            sys.exit(1)
        if not opts.force:
            # Prompt for confirmation (require explicit yes/y to proceed)
            confirm = input(
                f"Are you sure you want to remove certificate '{opts.name}'? "
                "Type 'y' or 'yes' to confirm: "
            ).strip().lower()
            if confirm not in ("yes", "y"):
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
    cert_cmds = add_parser_fn("cert",
                              help="create, list, remove, or show certificates",
                              description="Create, list, remove, or show certificates.")
    cert_subparsers = cert_cmds.add_subparsers(
        title="subcommands",
        metavar="",
        dest="cert_subcommands",
        required=True
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
        help="certificate file name; ignored for root-ca",
    )
    cert_create.set_defaults(func=create_cert)

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
        help="show compact certificate details",
    )
    cert_list.set_defaults(func=list_certs)

    cert_show = add_parser_fn(
        "show",
        help="show details for a certificate",
        subparser=cert_subparsers,
    )
    cert_show.add_argument("name", help="name of the certificate to show")
    cert_show.set_defaults(func=show_cert)

    cert_remove = add_parser_fn(
        "remove",
        help="remove a certificate",
        subparser=cert_subparsers,
    )
    cert_remove.add_argument("name", help="name of the certificate to remove")
    cert_remove.add_argument(
        "--force",
        action="store_true",
        help="remove without interactive confirmation",
    )
    # cert_remove.add_argument(
    #     "--remote",
    #     action="store_true",
    #     help="remove a remote certificate instead of a local certificate",
    # )
    cert_remove.set_defaults(func=remove_cert)
