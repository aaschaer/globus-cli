import platform
import webbrowser

import click

from globus_sdk import AuthClient, AccessTokenAuthorizer
# from globus_sdk.auth.oauth2_constants import DEFAULT_REQUESTED_SCOPES

from globus_cli.helpers import (
    start_local_server, is_remote_session, LocalServerError)
from globus_cli.safeio import safeprint
from globus_cli.parsing import common_options
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
def login_command(force, check, no_local_server, ssh):
    # fail if check is given with any options that are used in actual login
    if check and (force or no_local_server):
        raise click.UsageError(
            "--check cannot be used with options that require a login flow.")

    # determine which resource servers we need based on options
    if ssh:
        # auth is required for user data
        resource_servers = ["auth", ssh]
    else:
        resource_servers = ["auth", "transfer"]

    # check if the user is already logged in, and stop now if check is true
    logged_in = check_logged_in(resource_servers)
    if check:
        resource_server_string = (
            resource_servers[0] + " and " + resource_servers[1])
        if logged_in:
            safeprint(("The Globus CLI is authorized to make calls to {} on "
                       "your behalf.".format(resource_server_string)))
            return
        else:
            safeprint(("You have not authorized the Globus CLI to make calls "
                      "to {} on your behalf.".format(resource_server_string)))
            click.get_current_context().exit(1)

    # if not forcing, stop if user already logged in
    if not force and logged_in:
        safeprint(_LOGGED_IN_RESPONSE)
        return

    # get the scopes needed for this login
    scopes = get_scopes(resource_servers)

    # use a link login if remote session or user requested
    if no_local_server or is_remote_session():
        do_link_login_flow(scopes)
    # otherwise default to a local server login flow
    else:
        do_local_server_login_flow(scopes)


def check_logged_in(resource_servers):
    """
    Determines if the user has a valid refresh token for the required
    resources server. If no resource server is given, checks transfer
    and auth as a default.
    """
    # get the NativeApp client object
    native_client = internal_auth_client()

    # for each resource server required for login
    for server in resource_servers:
        # get any tokens in config for that resource server
        tokens = get_tokens_by_resource_server(server)
        refresh_token = tokens.get("refresh_token")
        # return false if no token exists or if it is no longer active
        if not refresh_token:
            return False
        res = native_client.oauth2_validate_token(refresh_token)
        if not res["active"]:
            return False

    return True


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

    # get the identity that the tokens were issued to (assumes auth in scopes)
    auth_client = AuthClient(authorizer=AccessTokenAuthorizer(
        tokens["auth.globus.org"]["access_token"]))
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
