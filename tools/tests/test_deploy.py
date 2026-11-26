"""What runs around the server: the container entrypoint, the Dockerfile it belongs to, the certificate script."""

from __future__ import annotations

import grp
import os
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = ROOT / "docker-entrypoint.sh"


# --- the container entrypoint -------------------------------------------------------------------------


def _unprivileged_user() -> str | None:
    """A non-root account whose name is also a group (what `useradd --user-group` makes in the image)."""
    for entry in pwd.getpwall():
        if entry.pw_uid == 0:
            continue
        try:
            grp.getgrnam(entry.pw_name)
        except KeyError:
            continue
        return entry.pw_name
    return None


RUN_AS = _unprivileged_user()
needs_root = pytest.mark.skipif(
    os.geteuid() != 0 or shutil.which("setpriv") is None or RUN_AS is None,
    reason="needs root, setpriv and an unprivileged account to drop to (as inside the container)",
)
REPORT = (
    'echo "uid=$(id -u) home_writable=$([ -w "$HOME" ] && echo yes || echo no) cert=${GRIZZLE_TLS_CERT:-}'
    ' key_readable=$([ -r "${GRIZZLE_TLS_KEY:-/nonexistent}" ] && echo yes || echo no)'
    ' data_writable=$([ -w "$GRIZZLE_DATA_DIR" ] && echo yes || echo no)'
    ' nnp=$(awk "/^NoNewPrivs:/{print \\$2}" /proc/self/status) caps=$(awk "/^CapEff:/{print \\$2}" /proc/self/status)"'
)


def _entrypoint(tmp_path, *command, **env) -> subprocess.CompletedProcess:
    base = {"PATH": os.environ["PATH"], "GRIZZLE_RUN_AS": RUN_AS or "", "GRIZZLE_DATA_DIR": str(tmp_path / "data"),
            "GRIZZLE_TLS_CERT": str(tmp_path / "certs" / "fullchain.pem"),
            "GRIZZLE_TLS_KEY": str(tmp_path / "certs" / "privkey.pem"),
            "GRIZZLE_CERT_COPY_DIR": str(tmp_path / "cert-copy")}
    base.update(env)
    command = command or ("sh", "-c", REPORT)
    script = tmp_path / "docker-entrypoint.sh"
    return subprocess.run(["sh", str(script), *command], env=base, capture_output=True, text=True, timeout=30)


@pytest.fixture
def volumes():
    """Root-owned volumes as an earlier image (which ran as root) left them.

    In a directory of their own that the unprivileged account can reach (pytest's temporary
    directories are private to root, and so may the checkout be), with a copy of the script.
    """
    tmp_path = Path(tempfile.mkdtemp(prefix="grizzle-entrypoint-"))
    tmp_path.chmod(0o755)
    try:
        shutil.copy(ENTRYPOINT, tmp_path / "docker-entrypoint.sh")
        (tmp_path / "docker-entrypoint.sh").chmod(0o755)
        yield _fill_volumes(tmp_path)
    finally:
        shutil.rmtree(tmp_path, ignore_errors=True)


def _fill_volumes(tmp_path: Path) -> Path:
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "state.json").write_text("{}")
    (tmp_path / "data" / "state.json").chmod(0o600)
    (tmp_path / "certs").mkdir()
    (tmp_path / "certs" / "fullchain.pem").write_text("CERT")
    (tmp_path / "certs" / "privkey.pem").write_text("KEY")
    (tmp_path / "certs" / "privkey.pem").chmod(0o600)
    return tmp_path


@needs_root
def test_entrypoint_drops_privileges_and_hands_over_the_volumes(volumes):
    result = _entrypoint(volumes)
    assert result.returncode == 0, result.stderr
    uid = pwd.getpwnam(RUN_AS).pw_uid
    fields = dict(part.split("=", 1) for part in result.stdout.split())
    assert fields["uid"] == str(uid) and fields["caps"] == "0000000000000000" and fields["nnp"] == "1"
    assert fields["data_writable"] == "yes" and fields["key_readable"] == "yes"
    assert fields["home_writable"] == "yes"  # HOME no longer says /root, which that user cannot enter
    assert (volumes / "data" / "state.json").stat().st_uid == uid
    # The key in the (read-only) certs volume is untouched; the server got a private copy.
    assert (volumes / "certs" / "privkey.pem").stat().st_uid == 0
    copy = volumes / "cert-copy" / "grizzle-certs" / "privkey.pem"
    assert fields["cert"] == str(volumes / "cert-copy" / "grizzle-certs" / "fullchain.pem")
    assert copy.read_text() == "KEY" and copy.stat().st_uid == uid and stat.S_IMODE(copy.stat().st_mode) == 0o600
    assert stat.S_IMODE(copy.parent.stat().st_mode) == 0o700
    assert result.stderr == ""


@needs_root
def test_entrypoint_passes_arguments_through_unchanged(volumes):
    result = _entrypoint(volumes, "sh", "-c", 'printf "[%s]" "$@"', "sh", "a b", "c  d", "")
    assert result.returncode == 0 and result.stdout == "[a b][c  d][]"


@needs_root
@pytest.mark.parametrize(
    "env,reason",
    [
        ({"GRIZZLE_RUN_AS": "no-such-user"}, "cannot switch to user"),
        ({"GRIZZLE_DATA_DIR": "/proc/sys/kernel"}, "is not writable"),
        ({"GRIZZLE_CERT_COPY_DIR": "/proc/nope/certs"}, "TLS key is not readable"),
    ],
)
def test_entrypoint_stays_root_rather_than_break_an_installation(volumes, env, reason):
    result = _entrypoint(volumes, **env)
    assert result.returncode == 0, result.stderr
    assert "uid=0 " in result.stdout
    assert reason in result.stderr and "running as root" in result.stderr


@needs_root
def test_entrypoint_does_nothing_when_told_to_stay_root_or_already_unprivileged(volumes):
    result = _entrypoint(volumes, GRIZZLE_RUN_AS="root")
    assert result.returncode == 0 and "uid=0 " in result.stdout and result.stderr == ""
    assert (volumes / "data" / "state.json").stat().st_uid == 0  # nothing was handed over

    uid = pwd.getpwnam(RUN_AS).pw_uid
    base = {"PATH": os.environ["PATH"], "GRIZZLE_DATA_DIR": str(volumes / "data"), "HOME": "/root"}
    as_user = ["setpriv", f"--reuid={RUN_AS}", f"--regid={RUN_AS}", "--init-groups"]
    script = str(volumes / "docker-entrypoint.sh")
    result = subprocess.run(  # `user:` in compose: the container never is root
        [*as_user, "sh", script, "sh", "-c", REPORT], env=base, capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0 and f"uid={uid} " in result.stdout and result.stderr == ""


def test_entrypoint_and_dockerfile_agree():
    dockerfile = (ROOT / "Dockerfile").read_text()
    entrypoint = ENTRYPOINT.read_text()
    assert 'ENTRYPOINT ["docker-entrypoint.sh"]' in dockerfile and '\nCMD ["grizzle-local"]' in dockerfile
    assert 'CMD ["grizzle-local", "healthcheck"]' in dockerfile  # the health check is the server asking itself
    for name in ("grizzle-local", "docker-entrypoint.sh"):  # both are found by name: they are on PATH
        assert f" /usr/local/bin/{name}\n" in dockerfile
    # The account the entrypoint drops to exists, with a group of its own name (setpriv --regid) and
    # the uid the entrypoint's advice names; the data directory is the same one, and that account's.
    assert "useradd --system --uid 10001 --user-group --home-dir /data " in dockerfile
    assert 'RUN_AS="${GRIZZLE_RUN_AS:-grizzle}"' in entrypoint and 'user: \\"10001:10001\\"' in entrypoint
    assert "GRIZZLE_DATA_DIR=/data" in dockerfile and 'DATA="${GRIZZLE_DATA_DIR:-/data}"' in entrypoint
    assert "chown grizzle:grizzle /data" in dockerfile
    assert os.access(ENTRYPOINT, os.X_OK)
    assert subprocess.run(["sh", "-n", str(ENTRYPOINT)]).returncode == 0  # parses as POSIX sh
    # The image is built from locked dependencies, and so are the Python tools.
    assert "COPY Cargo.toml Cargo.lock ./" in dockerfile and "cargo build --release --locked" in dockerfile
    locked = (ROOT / "requirements.txt").read_text()
    for line in locked.splitlines():  # every requirement is pinned exactly, with a hash
        if line and not line.startswith((" ", "#")):
            assert "==" in line and line.rstrip().endswith("\\"), line
    assert locked.count("--hash=sha256:") > 50


BIND_PROBE = (
    "import socket, sys\n"
    "caps = [l.split()[1] for l in open('/proc/self/status') if l.startswith('CapEff')][0]\n"
    "def bind(port):\n"
    "    try:\n"
    "        socket.socket().bind(('127.0.0.1', port)); return 'ok'\n"
    "    except OSError: return 'refused'\n"
    "print(caps, bind(int(sys.argv[1])))\n"
)


def _low_port() -> int | None:
    """A free port below the unprivileged range, if this system has one."""
    try:
        limit = int(Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text())
    except (OSError, ValueError):
        return None
    for port in range(min(limit, 1024) - 1, 0, -1):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return None


@needs_root
def test_entrypoint_keeps_only_the_bind_capability_for_a_low_port(volumes):
    """With host networking and GRIZZLE_TLS_PORT=443 the unprivileged server could not bind its
    port, and the container that started fine as root no longer started at all."""
    port = _low_port()
    if port is None:
        pytest.skip("every port is unprivileged here")
    result = _entrypoint(volumes, sys.executable, "-c", BIND_PROBE, str(port))
    assert result.stdout.split() == ["0000000000000000", "refused"], result.stderr  # default ports: nothing kept
    result = _entrypoint(volumes, sys.executable, "-c", BIND_PROBE, str(port), GRIZZLE_TLS_PORT="443")
    assert result.stdout.split() == ["0000000000000400", "ok"], result.stderr  # CAP_NET_BIND_SERVICE and nothing else
    result = _entrypoint(volumes, sys.executable, "-c", BIND_PROBE, str(port), GRIZZLE_PORT="80; echo injected")
    assert result.stdout.split() == ["0000000000000000", "refused"] and "injected" not in result.stdout


@needs_root
def test_entrypoint_checks_the_files_and_not_just_the_directory(volumes):
    """A volume whose ownership cannot be changed (root-squashed NFS, say) with a directory anyone may
    write: the directory test passed, root was dropped, and the server then could not open its own
    state file or database."""
    (volumes / "data").chmod(0o777)
    stub = volumes / "bin"
    stub.mkdir()
    (stub / "chown").write_text("#!/bin/sh\nexit 1\n")  # this filesystem refuses to change owners
    (stub / "chown").chmod(0o755)
    result = _entrypoint(volumes, PATH=f"{stub}:{os.environ['PATH']}")
    assert result.returncode == 0, result.stderr
    assert "uid=0 " in result.stdout and "or a file in it is not writable" in result.stderr
    assert (volumes / "data" / "state.json").stat().st_uid == 0


@needs_root
def test_entrypoint_follows_a_symlinked_data_directory(volumes):
    (volumes / "data").rename(volumes / "real-data")
    (volumes / "data").symlink_to(volumes / "real-data")
    result = _entrypoint(volumes)
    uid = pwd.getpwnam(RUN_AS).pw_uid
    assert f"uid={uid} " in result.stdout and result.stderr == "", result.stderr
    assert (volumes / "real-data" / "state.json").stat().st_uid == uid


@needs_root
def test_entrypoint_never_empties_the_directory_it_is_told_to_copy_certificates_to(volumes):
    """It used to `rm -rf` whatever GRIZZLE_CERT_COPY_DIR named. Naming the data directory emptied it."""
    result = _entrypoint(volumes, GRIZZLE_CERT_COPY_DIR=str(volumes / "data"))
    assert result.returncode == 0, result.stderr
    assert (volumes / "data" / "state.json").read_text() == "{}"
    assert (volumes / "data" / "grizzle-certs" / "privkey.pem").read_text() == "KEY"


def test_repository_keeps_unix_line_endings_for_what_runs_in_the_image():
    attributes = (ROOT / ".gitattributes").read_text()
    assert "*.sh" in attributes and "eol=lf" in attributes
    assert b"\r" not in ENTRYPOINT.read_bytes()
    compose = (ROOT / "docker-compose.yml").read_text()
    assert "no-new-privileges:true" in compose


# --- the certificate script -------------------------------------------------------------------------


def test_generated_certificate_is_a_server_certificate_not_a_ca(certs):
    """`openssl req -x509` makes a CA by default: whoever copied privkey.pem could have signed
    certificates for any site, valid wherever this certificate had been trusted."""
    text = subprocess.run(
        ["openssl", "x509", "-in", str(certs[0]), "-noout", "-text"], check=True, capture_output=True, text=True
    ).stdout
    assert "CA:FALSE" in text and "CA:TRUE" not in text
    assert "TLS Web Server Authentication" in text
    assert "DNS:ocpp.unitedchargers.com" in text and "DNS:connect-api.unitedchargers.com" in text
    assert stat.S_IMODE(certs[1].stat().st_mode) == 0o600
