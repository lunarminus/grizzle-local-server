#!/bin/sh
# Run the server as the unprivileged "grizzle" user.
#
# The container starts as root only so this script can make the volumes usable: data written by
# an earlier image (which ran as root) or a directory Docker has just created belongs to root.
# Then it switches user for good. If you set `user:` in compose (or `docker run --user`) the
# container never is root and this script simply runs the command.
#
# Dropping root must never be the reason an existing installation stops starting, so whenever
# the unprivileged user could not do its job (cannot switch user, data directory not writable,
# no place to put a readable copy of the TLS key) the script says so and carries on as root.
set -eu

RUN_AS="${GRIZZLE_RUN_AS:-grizzle}"
DATA="${GRIZZLE_DATA_DIR:-/data}"
CERT="${GRIZZLE_TLS_CERT:-/certs/fullchain.pem}"
KEY="${GRIZZLE_TLS_KEY:-/certs/privkey.pem}"
CERT_COPY="${GRIZZLE_CERT_COPY_DIR:-/run/grizzle-certs}"

if [ "$(id -u)" != "0" ] || [ "$RUN_AS" = "root" ]; then
    exec "$@"
fi

as_user() {
    setpriv --reuid="$RUN_AS" --regid="$RUN_AS" --init-groups --no-new-privs "$@"
}

stay_root() {
    echo "docker-entrypoint: $1; running as root" >&2
    shift
    exec "$@"
}

if ! as_user true 2>/dev/null; then
    stay_root "cannot switch to user '$RUN_AS' (unknown user, or no SETUID/SETGID capability)" "$@"
fi

mkdir -p "$DATA" 2>/dev/null || true
chown -R "$RUN_AS:$RUN_AS" "$DATA" 2>/dev/null || true
if ! as_user sh -c 'test -d "$1" && test -w "$1" && test -x "$1"' sh "$DATA" 2>/dev/null; then
    stay_root "'$DATA' is not writable by '$RUN_AS' (read-only or root-squashed volume?)" "$@"
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

exec setpriv --reuid="$RUN_AS" --regid="$RUN_AS" --init-groups --no-new-privs "$@"
