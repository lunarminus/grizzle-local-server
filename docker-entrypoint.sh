#!/bin/sh
# Run the server as the unprivileged "grizzle" user.
#
# The container starts as root only so this script can make the volumes usable: data written by
# an earlier image (which ran as root) or a directory Docker has just created belongs to root.
# Then it switches user for good. If you set `user:` in compose (or `docker run --user`) the
# container never is root and this script simply runs the command.
#
# Dropping root must never be the reason an existing installation stops starting, so whenever
# the unprivileged user could not do its job (cannot switch user, data directory or the files in
# it not writable, no place to put a readable copy of the TLS key, a port it may not bind) the
# script says so and carries on as root. GRIZZLE_RUN_AS=root keeps root on purpose.
set -eu

RUN_AS="${GRIZZLE_RUN_AS:-grizzle}"
DATA="${GRIZZLE_DATA_DIR:-/data}"
CERT="${GRIZZLE_TLS_CERT:-/certs/fullchain.pem}"
KEY="${GRIZZLE_TLS_KEY:-/certs/privkey.pem}"
# Always a directory of our own inside the one named: it is emptied on every start, and
# GRIZZLE_CERT_COPY_DIR=/data must not mean "empty /data".
CERT_COPY="${GRIZZLE_CERT_COPY_DIR:-/run}/grizzle-certs"

# Can whoever runs this use the data directory: the directory itself and the files the server
# opens in it? (A directory can be writable while state.json in it is someone else's.)
# shellcheck disable=SC2016  # the $1 belongs to the inner shell
CAN_USE_DATA='test -d "$1" && test -w "$1" && test -x "$1" || exit 1
for file in "$1"/state.json "$1"/state.tmp "$1"/history.sqlite "$1"/history.sqlite-journal "$1"/history.sqlite-wal; do
    [ ! -e "$file" ] || { [ -r "$file" ] && [ -w "$file" ]; } || exit 1
done'

if [ "$(id -u)" != "0" ] || [ "$RUN_AS" = "root" ]; then
    exec "$@"
fi

# A port below the kernel's unprivileged range needs a capability to bind. Inside a container's
# own network namespace Docker lets every port be bound, so this only matters with host
# networking (network_mode: host with GRIZZLE_TLS_PORT=443, say). Keep that one capability then,
# and nothing else.
CAPS=""
LOW_PORTS_END="$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)"
for port in "${GRIZZLE_PORT:-9000}" "${GRIZZLE_TLS_PORT:-8443}"; do
    case "$port" in
    '' | *[!0-9]*) continue ;;
    esac
    if [ "$port" -gt 0 ] && [ "$port" -lt "$LOW_PORTS_END" ]; then
        CAPS="--inh-caps=+net_bind_service --ambient-caps=+net_bind_service"
    fi
done

as_user() {
    # shellcheck disable=SC2086  # CAPS is two options or none: it has to be split
    setpriv --reuid="$RUN_AS" --regid="$RUN_AS" --init-groups --no-new-privs $CAPS "$@"
}

stay_root() {
    echo "docker-entrypoint: $1; running as root" >&2
    shift
    if ! sh -c "$CAN_USE_DATA" sh "$DATA" 2>/dev/null; then
        # Root without its capabilities (cap_drop: ALL) is no better off than anybody else.
        echo "docker-entrypoint: root cannot write '$DATA' either. Run the container as the owner of that" \
            "directory (user: \"10001:10001\" in compose), or allow the SETUID, SETGID and CHOWN capabilities" >&2
    fi
    exec "$@"
}

if ! as_user true 2>/dev/null; then
    if [ -n "$CAPS" ] && CAPS="" as_user true 2>/dev/null; then
        stay_root "a port below $LOW_PORTS_END is configured and '$RUN_AS' cannot be allowed to bind it here" "$@"
    fi
    stay_root "cannot switch to user '$RUN_AS' (unknown user, or no SETUID/SETGID capability)" "$@"
fi

mkdir -p "$DATA" 2>/dev/null || true
# -H: if the data directory is a symbolic link, hand over what it points to, not the link.
chown -R -H "$RUN_AS:$RUN_AS" "$DATA" 2>/dev/null || true
if ! as_user sh -c "$CAN_USE_DATA" sh "$DATA" 2>/dev/null; then
    stay_root "'$DATA' or a file in it is not writable by '$RUN_AS' (read-only or root-squashed volume?)" "$@"
fi

# The TLS key is normally mounted read-only and readable by its owner alone. Hand the
# unprivileged user a private copy instead of keeping root for the sake of one file.
if [ -f "$CERT" ] && [ -f "$KEY" ] &&
    ! as_user sh -c 'test -r "$1" && test -r "$2"' sh "$CERT" "$KEY" 2>/dev/null; then
    if rm -rf "$CERT_COPY" 2>/dev/null &&
        mkdir -p "$CERT_COPY" 2>/dev/null &&
        chmod 0700 "$CERT_COPY" &&
        cp "$CERT" "$CERT_COPY/fullchain.pem" 2>/dev/null &&
        cp "$KEY" "$CERT_COPY/privkey.pem" 2>/dev/null &&
        chmod 0600 "$CERT_COPY/fullchain.pem" "$CERT_COPY/privkey.pem" &&
        chown -R "$RUN_AS:$RUN_AS" "$CERT_COPY" 2>/dev/null; then
        export GRIZZLE_TLS_CERT="$CERT_COPY/fullchain.pem" GRIZZLE_TLS_KEY="$CERT_COPY/privkey.pem"
    else
        stay_root "the TLS key is not readable by '$RUN_AS' and '$CERT_COPY' is not writable" "$@"
    fi
fi

# HOME still says /root, which the unprivileged user cannot enter: tools that keep something
# under ~ (the firmware tool's token file) get the data directory instead.
export HOME="$DATA"
# shellcheck disable=SC2086
exec setpriv --reuid="$RUN_AS" --regid="$RUN_AS" --init-groups --no-new-privs $CAPS "$@"
