"""The S3 identity configuration — the file that decides who can write.

SeaweedFS's S3 gateway has one behaviour worth understanding before reading
these tests: with no `-config` argument it runs with **no identities at all**,
and in that mode every request is permitted. Authorisation is not "on by
default and configured here"; it is off until this file is supplied.

Two things therefore have to hold, and neither is checked by anything else:

  1. the gateway is actually started with -config
  2. the identity with no credentials — the anonymous one — has Read and
     nothing else

An identity block in SeaweedFS with no `credentials` key matches unsigned
requests. So `public-read` is not a named account anyone logs into; it is the
rule for the entire internet. Adding "Write" to it would make the bucket
world-writable, silently, with no error anywhere.

These are file reads. They need no infrastructure and run in milliseconds,
which is the point: the failure they guard against is a config edit, and a
config edit is exactly what does not get caught by testing the services.
"""

import json
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.contract

REPO = Path(__file__).resolve().parents[2]
TEMPLATE = REPO / "config" / "s3.json.template"
COMPOSE = REPO / "docker-compose.yml"

# Anything beyond Read hands out mutation rights.
MUTATING_ACTIONS = {"Write", "Admin", "Tagging", "DeleteBucket", "WriteAcp"}


def load_template():
    """Parse the template, leaving ${VAR} placeholders as literal strings."""
    assert TEMPLATE.is_file(), f"expected the identity template at {TEMPLATE}"
    return json.loads(TEMPLATE.read_text())


def identities():
    return load_template().get("identities", [])


def anonymous_identities():
    """Identities with no credentials — these match unsigned requests."""
    return [i for i in identities() if not i.get("credentials")]


# --------------------------------------------------------------------------- #
# The template is well-formed
# --------------------------------------------------------------------------- #

def test_the_template_exists_and_is_valid_json():
    config = load_template()
    assert "identities" in config, "s3.json.template has no identities key"


def test_at_least_one_identity_is_defined():
    """An empty identities list is the same as no config: everything allowed."""
    assert identities(), "no identities are defined — the gateway would allow everything"


def test_every_identity_has_a_name():
    unnamed = [i for i in identities() if not i.get("name")]
    assert not unnamed, f"{len(unnamed)} identities have no name"


def test_identity_names_are_unique():
    names = [i.get("name") for i in identities()]
    assert len(names) == len(set(names)), f"duplicate identity names: {names}"


def test_every_identity_declares_actions():
    """An identity with no actions is dead weight; more importantly, its absence
    usually means the block was half-edited."""
    for identity in identities():
        assert identity.get("actions"), f"identity {identity.get('name')!r} declares no actions"


# --------------------------------------------------------------------------- #
# The anonymous identity
# --------------------------------------------------------------------------- #

def test_there_is_exactly_one_anonymous_identity():
    anonymous = anonymous_identities()
    assert len(anonymous) == 1, (
        f"expected one credential-less identity, found {len(anonymous)}: "
        f"{[i.get('name') for i in anonymous]}. Each one is a separate rule "
        "applied to unsigned requests."
    )


def test_the_anonymous_identity_cannot_write():
    """The check this whole file exists for."""
    for identity in anonymous_identities():
        granted = set(identity.get("actions", []))
        escalation = granted & MUTATING_ACTIONS
        assert not escalation, (
            f"the anonymous identity {identity.get('name')!r} grants {sorted(escalation)}. "
            "It has no credentials, so this applies to every unsigned request — "
            "the bucket would be writable by anyone who can reach the gateway."
        )


def test_the_anonymous_identity_grants_only_read():
    for identity in anonymous_identities():
        assert set(identity.get("actions", [])) <= {"Read", "List"}, (
            f"{identity.get('name')!r} grants {identity.get('actions')}; only "
            "Read and List are safe for unauthenticated callers"
        )


# --------------------------------------------------------------------------- #
# Credentialed identities
# --------------------------------------------------------------------------- #

def test_credentials_are_placeholders_not_literals():
    """The template is committed. Anything concrete in it is a published secret."""
    placeholder = re.compile(r"^\$\{[A-Z0-9_]+\}$")
    for identity in identities():
        for credential in identity.get("credentials", []):
            for field in ("accessKey", "secretKey"):
                value = credential.get(field, "")
                assert placeholder.match(value), (
                    f"identity {identity.get('name')!r} has a literal {field} in "
                    f"the committed template: {value[:12]!r}... Use ${{VAR}} and "
                    "render it at deploy time."
                )


def test_every_credential_has_both_halves():
    for identity in identities():
        for credential in identity.get("credentials", []):
            assert credential.get("accessKey"), f"{identity.get('name')!r}: missing accessKey"
            assert credential.get("secretKey"), f"{identity.get('name')!r}: missing secretKey"


def test_admin_rights_belong_only_to_credentialed_identities():
    for identity in identities():
        if "Admin" in identity.get("actions", []):
            assert identity.get("credentials"), (
                f"identity {identity.get('name')!r} has Admin but no credentials — "
                "that grants administration to unsigned requests"
            )


def test_the_rendered_config_is_not_committed():
    """s3.json holds real keys once rendered. Only the template belongs in git."""
    rendered = REPO / "config" / "s3.json"
    assert not rendered.exists(), (
        f"{rendered} is present in the repository. It is the rendered file and "
        "contains real credentials; only s3.json.template should be committed."
    )


# --------------------------------------------------------------------------- #
# The gateway is started with the config
# --------------------------------------------------------------------------- #

def test_compose_exists():
    assert COMPOSE.is_file(), f"expected {COMPOSE}"


def s3_command():
    """The S3 gateway's command line, read out of docker-compose.yml."""
    text = COMPOSE.read_text()
    match = re.search(r"command:\s*'([^']*\bs3\b[^']*)'", text)
    if not match:
        match = re.search(r'command:\s*"([^"]*\bs3\b[^"]*)"', text)
    return match.group(1) if match else None


def test_the_s3_gateway_is_configured():
    command = s3_command()
    assert command, "no s3 gateway command found in docker-compose.yml"


def test_the_s3_gateway_is_started_with_an_identity_config():
    """Without -config the gateway ignores identities entirely and permits
    every request. This is the single most consequential flag in the file."""
    command = s3_command()
    assert command and "-config=" in command, (
        f"the s3 command does not pass -config: {command!r}. Without it "
        "SeaweedFS runs with no identities and allows anonymous writes."
    )


def test_the_config_path_is_mounted_into_the_container():
    command = s3_command() or ""
    match = re.search(r"-config=(\S+)", command)
    assert match, "could not read the -config path"
    config_path = match.group(1)

    directory = config_path.rsplit("/", 1)[0]
    assert f"{directory}'" in COMPOSE.read_text() or directory in COMPOSE.read_text(), (
        f"the s3 gateway reads {config_path} but nothing mounts {directory} — "
        "the gateway would start with no identity file"
    )
