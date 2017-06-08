import platform
import webbrowser
import pyperclip
import click

from globus_cli.helpers import (
    start_local_server, is_remote_session, LocalServerError)
from globus_cli.safeio import safeprint
from globus_cli.parsing import common_options
from globus_cli.services.auth import get_auth_client
from globus_cli.config import (
    WHOAMI_ID_OPTNAME, WHOAMI_USERNAME_OPTNAME,
    WHOAMI_EMAIL_OPTNAME, WHOAMI_NAME_OPTNAME,
    internal_auth_client, write_option,
    get_tokens_by_resource_server, write_tokens_by_resource_server)


_SHARED_EPILOG = ("""\

You can always check your current identity with
  globus whoami

Logout of the Globus CLI with
  globus logout
""")

_LOGIN_EPILOG = ("""\

You have successfully logged in to the Globus CLI as {}
""") + _SHARED_EPILOG

_LOGGED_IN_RESPONSE = ("""\
You are already logged in!

You may force a new login with
  globus login --force
""") + _SHARED_EPILOG


@click.command('login',
               short_help=('Login to Globus to get credentials for '
                           'the Globus CLI'),
               help=('Get credentials for the Globus CLI. '
                     'Necessary before any Globus CLI commands which require '
                     'authentication will work'))
@common_options(no_format_option=True, no_map_http_status_option=True)
@click.option('--force', is_flag=True,
              help=('Do a fresh login, ignoring any existing credentials'))
@click.option("--check", is_flag=True,
              help=("Only check if the user already has existing credentials "
                    "without doing a login flow. Mutually exclusive with "
                    "--force and --no-local-server"))
@click.option("--no-local-server", is_flag=True,
              help=("Manual login by copying and pasting an auth code. "
                    "This will be implied if using a remote connection."))
@click.option("--ssh", metavar="FQDN", default=None,
              help=("Login to Globus to give the CLI credentials for the "
                    "SSH server with the given Fully Qualified Domain Name."))
@click.option("--copy", is_flag=True,
              help=("If using ssh, attempts to copy the access token to the "
                    "clipboard. Prints token to stdout if unable to do so."))
def login_command(force, check, no_local_server, ssh, copy):
    # confirm that options are valid
    if check and (force or no_local_server):
        raise click.UsageError(
            "--check cannot be used with options that require a login flow.")
    if copy and not ssh:
        raise click.UsageError(
            "--copy can only be used with --ssh.")

    # determine which resource servers we need based on options,
    # auth and transfer are always required.
    resource_servers = ["auth", "transfer"]
    if ssh:
        resource_servers.append(ssh)

    # get the list of resource servers we do and don't have valid tokens for
    logged_in, not_logged_in = check_logged_in(resource_servers)
    if check:

        # still attempt copy if checking
        if copy:
            attempt_copy(ssh)

        logged_string = (" ".join(logged_in[:-1]) +
                         (" and " if len(logged_in) > 1 else "") +
                         "".join(logged_in[-1:]))
        not_logged_string = (" ".join(not_logged_in[:-1]) +
                             (" or " if len(not_logged_in) > 1 else "") +
                             "".join(not_logged_in[-1:]))

        # print which of the required servers the CLI is/isn't authorized for
        # exit 0 if authorized for all, 1 if not authorized for some
        if len(not_logged_in) == 0:
            safeprint(("You have authorized the Globus CLI to make calls to "
                       "{} on your behalf".format(logged_string)))
            return
        else:
            safeprint(("You have not authorized the Globus CLI to make calls "
                       "to {} on your behalf.".format(not_logged_string)))
            if len(logged_in):
                safeprint(("But you have authorized the Globus CLI "
                           "to make calls to {} on your behalf."
                           .format(logged_string)))
            click.get_current_context().exit(1)

    # if not forcing, stop if user already logged in for all resource servers
    if not force and len(not_logged_in) == 0:
        safeprint(_LOGGED_IN_RESPONSE)

        # still attempt copy even if logged in
        if copy:
            attempt_copy(ssh)

        return

    # get the scopes needed for this login
    if force:
        scopes = get_scopes(resource_servers)
    # if not forcing, only request scopes for servers we don't have tokens for
    else:
        scopes = get_scopes(not_logged_in)

    # use a link login if remote session or user requested
    if no_local_server or is_remote_session():
        do_link_login_flow(scopes)
    # otherwise default to a local server login flow
    else:
        do_local_server_login_flow(scopes)

    # output login epilog (also confirms successful login)
    output_epilog()

    # if copy given attempt to copy the ssh access token to the clipboard
    if copy:
        attempt_copy(ssh)


def check_logged_in(resource_servers):
    """
    For a given list of resource_servers, returns a a tuple of two lists for
    the servers that the user does and does not have a valid refresh_token for.
    """
    # get the NativeApp client object
    native_client = internal_auth_client()

    not_logged_in = []
    logged_in = []

    # for each resource server required for login
    for server in resource_servers:
        # get any tokens in config for that resource server
        tokens = get_tokens_by_resource_server(server)
        refresh_token = tokens.get("refresh_token")
        # return false if no token exists or if it is no longer active
        if not refresh_token:
            not_logged_in.append(server)
            continue
        res = native_client.oauth2_validate_token(refresh_token)
        if not res["active"]:
            not_logged_in.append(server)
            continue
        logged_in.append(server)

    return (logged_in, not_logged_in)


def get_scopes(resource_servers):
    """
    Gets the scopes required for a login flow.
    """
    scopes = []
    for server in resource_servers:

        if server == "auth":
            scopes.extend(["openid", "profile", "email"])

        elif server == "transfer":
            scopes.append("urn:globus:auth:scope:transfer.api.globus.org:all")

        else:
            # TODO: verify the server, and determine what scopes it needs
            # for now, just return the "all" scope for each server
            scopes.append(
                "urn:globus:auth:scope:{}:all".format(server))
    return scopes


def do_link_login_flow(scopes):
    """
    Prompts the user with a link to authorize the CLI to act on their behalf.
    """
    # get the NativeApp client object
    native_client = internal_auth_client()

    # start the Native App Grant flow, prefilling the
    # named grant label on the consent page if we can get a
    # hostname for the local system
    label = platform.node() or None
    native_client.oauth2_start_flow(
        requested_scopes=scopes,
        refresh_tokens=True, prefill_named_grant=label)

    # prompt
    linkprompt = 'Please login to Globus here'
    safeprint('{0}:\n{1}\n{2}\n{1}\n'
              .format(linkprompt, '-' * len(linkprompt),
                      native_client.oauth2_get_authorize_url()))

    # come back with auth code
    auth_code = click.prompt(
        'Enter the resulting Authorization Code here').strip()

    # finish login flow
    exchange_code_and_update_config(native_client, auth_code)


def do_local_server_login_flow(scopes):
    """
    Starts a local http server, opens a browser to have the user login,
    and gets the code redirected to the server (no copy and pasting required)
    """
    safeprint(
        "You are running 'globus login', which should automatically open "
        "a browser window for you to login.\n"
        "If this fails or you experience difficulty, try "
        "'globus login --no-local-server'"
        "\n---")
    # start local server and create matching redirect_uri
    with start_local_server(listen=('127.0.0.1', 0)) as server:
        _, port = server.socket.getsockname()
        redirect_uri = 'http://localhost:{}'.format(port)

        # get the NativeApp client object and start a flow
        # if available, use the system-name to prefill the grant
        label = platform.node() or None
        native_client = internal_auth_client()
        native_client.oauth2_start_flow(
            requested_scopes=scopes,
            refresh_tokens=True, prefill_named_grant=label,
            redirect_uri=redirect_uri)
        url = native_client.oauth2_get_authorize_url()

        # open web-browser for user to log in, get auth code
        webbrowser.open(url, new=1)
        auth_code = server.wait_for_code()

    if isinstance(auth_code, LocalServerError):
        safeprint('Login failed: {}'.format(auth_code), write_to_stderr=True)
        click.get_current_context().exit(1)
    elif isinstance(auth_code, Exception):
        safeprint('Login failed with unexpected error:\n{}'.format(auth_code),
                  write_to_stderr=True)
        click.get_current_context().exit(1)

    # finish login flow
    exchange_code_and_update_config(native_client, auth_code)


def exchange_code_and_update_config(native_client, auth_code):
    """
    Finishes login flow after code is gotten from command line or local server.
    Exchanges code for tokens and gets user info from auth.
    Stores tokens and user info in config.
    """
    # do a token exchange with the given code
    res = native_client.oauth2_exchange_code_for_tokens(auth_code)
    tokens = res.by_resource_server

    for server in tokens:

        # backwards compatibility
        if server == "transfer.api.globus.org":
            server_name = "transfer"
        elif server == "auth.globus.org":
            server_name = "auth"
        else:
            server_name = server

        # revoke any existing tokens
        existing_tokens = get_tokens_by_resource_server(server_name)
        for token_type in ["access_token", "refresh_token"]:
            token = existing_tokens.get(token_type)
            if token:
                native_client.oauth2_revoke_token(token)

        # write new token data
        write_tokens_by_resource_server(server_name, tokens[server])


def attempt_copy(ssh_server):
    """
    Attempts to copy the access_token for the given ssh resource server
    to the clipboard. Prints token to stdout if unable to do so.
    """
    token = get_tokens_by_resource_server(ssh_server)["access_token"]
    fallback = False

    if not token:
        safeprint("Unable to copy access token: no access token exists.")

    elif is_remote_session():
        safeprint(("Unable to copy access token to clipboard over remote "
                   "session."))
        fallback = True

    else:
        try:
            pyperclip.copy(token)
            safeprint("Access token copied to clipboard.\n")
        except Exception as e:
            safeprint("Copy failed on: {}".format(e))
            fallback = True

    # if we were unable to copy for some reason, fall back to print
    if fallback:
        safeprint(("Displaying access token for manual copying:\n{}\n"
                   .format(token)))


def output_epilog():
    """
    Gets the newly-logged in identity, and prints the epilog.
    Will fail if called before a successful login.
    """
    # get the identity that the tokens were issued to
    auth_client = get_auth_client()
    res = auth_client.get('/p/whoami')

    # get the primary identity
    # note: Auth's /p/whoami response does not mark an identity as
    # "primary" but by way of its implementation, the first identity
    # in the list is the primary.
    identity = res['identities'][0]

    # write whoami data to config
    write_option(WHOAMI_ID_OPTNAME, identity['id'])
    write_option(WHOAMI_USERNAME_OPTNAME, identity['username'])
    write_option(WHOAMI_EMAIL_OPTNAME, identity['email'])
    write_option(WHOAMI_NAME_OPTNAME, identity['name'])

    safeprint(_LOGIN_EPILOG.format(identity['username']))
