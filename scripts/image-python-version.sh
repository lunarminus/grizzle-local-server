#!/bin/sh
# Prints the Python version the image is built on: the X.Y of "FROM python:X.Y-slim" in the Dockerfile.
# CI installs the version this prints and runs the tests on it (.github/workflows/ci.yml), so when the
# base image is updated the tests run on the Python it brings.
# Usage: scripts/image-python-version.sh [Dockerfile]
set -eu
dockerfile="${1:-$(dirname "$0")/../Dockerfile}"
[ -f "$dockerfile" ] && [ -r "$dockerfile" ] || { echo "$0: cannot read $dockerfile" >&2; exit 1; }
# Every FROM line that names the python image counts, whatever options come before the image and
# whatever follows the version in its tag. A line it cannot read a version from, or two lines with
# different versions, is an error: a guess would have the tests run on some other Python unnoticed.
awk '
  { sub(/\r$/, "") }
  tolower($1) == "from" {
    image = 2
    while (image <= NF && $image ~ /^--/) image++
    if ($image != "python" && $image !~ /^python[:@]/) next
    tag = $image
    sub(/^python:?/, "", tag)
    sub(/@.*/, "", tag)
    if (tag !~ /^[0-9]+\.[0-9]+(\.[0-9]+)?(-[A-Za-z0-9._-]+)?$/) { unreadable = $0; exit }
    match(tag, /^[0-9]+\.[0-9]+/)
    version = substr(tag, 1, RLENGTH)
    if (found != "" && found != version) { second = version; exit }
    found = version
  }
  END {
    if (unreadable != "") problem = "no Python version (python:X.Y...) in \"" unreadable "\""
    else if (second != "") problem = "FROM lines with different Python versions: " found " and " second
    else if (found == "") problem = "no FROM line names the python image"
    if (problem != "") { print problem > "/dev/stderr"; exit 1 }
    print found
  }
' "$dockerfile" || { echo "$0: cannot tell which Python $dockerfile builds the image on" >&2; exit 1; }
