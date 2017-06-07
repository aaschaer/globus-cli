import click
import globus_sdk

from globus_cli.safeio import safeprint
from globus_cli.parsing import common_options
from globus_cli.config import (
    WHOAMI_ID_OPTNAME, WHOAMI_USERNAME_OPTNAME,
    WHOAMI_EMAIL_OPTNAME, WHOAMI_NAME_OPTNAME,
    EXPECTED_RESOURCE_SERVERS_OPTNAME,
    internal_auth_client, remove_option, lookup_option,
    get_all_resource_servers, get_expected_resource_servers,
    get_tokens_by_resource_server, remove_tokens_by_resource_server)


_RESCIND_HELP = """
Rescinding Consents
-------------------
The logout command only revokes tokens that it can see in its storage.
Since logout ran into warnings in storage you may want to manually rescind
the Globus CLI consent on the Manage Consents Page:

    https://auth.globus.org/consents
"""


_LOGOUT_EPILOG = """\
You are now logged out of the Globus CLI.
Before attempting any further CLI commands, you will have to login again using

  globus login
"""


@click.command('logout',
               short_help='Logout of the Globus CLI',
               help=('Logout of the Globus CLI. '
                     'Removes your Globus tokens from local storage, '
                     'and revokes them so that they cannot be used anymore'))
@common_options(no_format_option=True, no_map_http_status_option=True)
@click.confirmation_option(prompt='Are you sure you want to logout?',
                           help='Automatically say "yes" to all prompts')
@click.option("--ssh", metavar="FQDN", default=None,
              help=("Only remove tokens for the SSH server with the given "
                    "Fully Qualified Domain Name."))
def logout_command(ssh):
    # check for username -- if not set, probably not logged in
    username = lookup_option(WHOAMI_USERNAME_OPTNAME)
    if not username:
        safeprint(("Your username is not set. You may not be logged in. "
                   "Attempting logout anyway...\n"))

    if ssh:
        safeprint("Removing tokens for {}{}.\n".format(
            ssh, " as " + username if username else ""))
    else:
        safeprint("Logging out of Globus{}.\n".format(" as " + username
                                                      if username else ''))

    # build the NativeApp client object
    native_client = internal_auth_client()
    print_rescind_help = False

    # if ssh is given, only remove and rescind tokens for the given FQDN
    if ssh:
        expected_resource_servers = [ssh]
        remove_unexpected = False
    # otherwise rescind and remove all tokens in config
    else:
        expected_resource_servers = get_expected_resource_servers()
        remove_unexpected = True

    # rescind and remove all tokens for all resource servers
    for resource_server in get_all_resource_servers():

        # if we weren't expecting this resource server give a warning
        if resource_server not in expected_resource_servers:
            if remove_unexpected:
                safeprint(("Warning: Found tokens for unexpected resource "
                           "server: {}.".format(resource_server)))
                print_rescind_help = True
            else:
                continue  # move onto the next resource server

        tokens = get_tokens_by_resource_server(resource_server)

        for token_type in ["access_token", "refresh_token"]:

            token = tokens.get(token_type)
            if token:
                # try to revoke token, stop logout on network error
                try:
                    native_client.oauth2_revoke_token(token)
                except globus_sdk.NetworkError:
                    safeprint(("Failed to reach Globus to revoke tokens. "
                               "Because we cannot revoke these tokens, "
                               "cancelling logout."))
                    click.get_current_context().exit(1)

            else:
                safeprint(("Warning: Found no {} for resource server {}."
                           .format(token_type, resource_server)))
                print_rescind_help = True

            # remove token info for this server from config
            remove_tokens_by_resource_server(resource_server)
            try:
                expected_resource_servers.remove(resource_server)
            except ValueError:
                pass

    # if any expected servers are left give a warning:
    if expected_resource_servers:
        safeprint(("Warning: Did not find any tokens for the following "
                   "expected resource servers:\n{}"
                   .format(" ".join(expected_resource_servers))))
        print_rescind_help = True

    # if we removed all tokens, no need to expect any resource servers
    if remove_unexpected:
        remove_option(EXPECTED_RESOURCE_SERVERS_OPTNAME)

    # remove whoami data on full logout
    if not ssh:
        for whoami_opt in (WHOAMI_ID_OPTNAME, WHOAMI_USERNAME_OPTNAME,
                           WHOAMI_EMAIL_OPTNAME, WHOAMI_NAME_OPTNAME):
            remove_option(whoami_opt)

    # if print_rescind_help is true, we printed warnings above
    # so, jam out an extra newline as a separator
    if print_rescind_help:
        safeprint("\n")
    # only print full epilog for full logout
    if not ssh:
        safeprint(_LOGOUT_EPILOG)
    else:
        safeprint("Removed all tokens for {}.".format(ssh))

    # if an expected token wasn't found or an unexpected token was, its
    # possible that the config file was removed or modified without logout
    # in that case, the user should rescind the CLI consent to invalidate any
    # potentially leaked refresh tokens, so print the help on that
    if print_rescind_help:
        safeprint(_RESCIND_HELP)
