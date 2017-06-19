import click
import six
import os
import pty
import psutil

from globus_cli.helpers import is_verbose, is_remote_session
from globus_cli.parsing import common_options, HiddenOption
from globus_cli.commands.login import (
    get_scopes, do_link_login_flow, do_local_server_login_flow)
from globus_cli.config import (
    get_tokens_by_resource_server, write_tokens_by_resource_server,
    internal_auth_client)


# global bools for ssh_read state, starts with looking for prompt
looking_for_prompt = True
checking_for_success = False
normal_read = False


@click.command("ssh", short_help="Use oauth over ssh.",
               context_settings={"ignore_unknown_options": True},
               help=("Uses the Globus CLI to get an oauth access token for "
                     "the given Fully Qualified Domain Name, then starts ssh "
                     "with that domain. Any additional options or arguments "
                     "after the FQDN will be passed to ssh."))
@common_options(no_format_option=True, no_map_http_status_option=True)
@click.argument("FQDN")
@click.option("--no-local-server", is_flag=True,
              help=("If a login flow is needed, use manual login by "
                    "copying and pasting an auth code. "
                    "This will be implied if using a remote connection."))
@click.option("--password", "-p", cls=HiddenOption, default=None)
@click.argument("ssh_args", nargs=-1, type=click.UNPROCESSED)
def ssh_command(fqdn, no_local_server, password, ssh_args):

    # since -v is also a valid ssh argument, pass it along if we are verbose
    if is_verbose():
        ssh_args += ("-v",)

    # TODO: remove this
    if password:
        token = password

    # either get access token or do login flow to get one
    else:
        client = internal_auth_client()
        tokens = get_tokens_by_resource_server(fqdn)

        # if we have a refresh_token, check if its still active
        ref_active = False
        if tokens["refresh_token"]:
            ref_active = client.oauth2_validate_token(
                tokens["refresh_token"])["active"]

        # if we don't have a valid refresh token do login flow
        if not ref_active:

            scopes = get_scopes([fqdn])

            # use a link login if remote session or user requested
            if no_local_server or is_remote_session():
                do_link_login_flow(scopes)
            # otherwise default to a local server login flow
            else:
                do_local_server_login_flow(scopes)

            # get tokens again after login flow is done
            tokens = get_tokens_by_resource_server(fqdn)
            token = tokens["access_token"]

        # if we do have a valid refresh token
        else:
            # check if our access token is valid
            acc_active = client.oauth2_validate_token(
                tokens["access_token"])["active"]

            # if not, get a new one and update config
            if not acc_active:
                ref_res = client.oauth2_refresh_token(tokens["refresh_token"])
                token = ref_res["access_token"]
                write_tokens_by_resource_server(fqdn, ref_res)

    def _get_ssh_process():
        """
        Returns a psutil.Process of the ssh process.
        Assumes exactly one child has been spawned by the parent calling this.
        """
        parent = psutil.Process(os.getpid())
        return psutil.Process(parent.children()[0].pid)

    def ssh_read(fd):
        """
        Function to be passed to pty.spawn as the master_read function.
        Reads from the given pseudo terminal file descriptor.
        If the line looks like a password prompt, writes the access token.
        Otherwise returns the line normally.
        """
        global looking_for_prompt
        global checking_for_success
        global normal_read
        data = os.read(fd, 1024)

        if not normal_read:
            # if we have gotten a command prompt, likely in normal reading
            prompt_chars = ["$", "%", ">"]
            if any(char in data for char in prompt_chars):
                looking_for_prompt = False
                checking_for_success = False
                normal_read = True

        if looking_for_prompt:
            # if password in data, likely password prompt
            if b"assword" in data:
                os.write(fd, six.b(token) + b"\n")
                looking_for_prompt = False
                checking_for_success = True
                return b"Access token sent.\n"

        if checking_for_success:
            # denied, try again, and password are likely markers of a failure
            fail_terms = [b"enied", b"gain", b"assword"]
            if any(term in data for term in fail_terms):
                # terminate ssh process and return a failure message.
                _get_ssh_process().terminate()
                return b"Access token not accepted, terminating ssh.\n"

        return data

    # start ssh pty with the FQDN using any additional arguments
    ssh_args = (b"ssh", six.b(fqdn),) + ssh_args

    # spawn ssh in a pseudo terminal
    pty.spawn(ssh_args, ssh_read)

    # and exit with its exit code when it completes
    exit_code = _get_ssh_process().wait()
    click.get_current_context().exit(exit_code)
