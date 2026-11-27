#!/bin/sh
# pre-commit hook entry for Loophole (issue #53).
#
# pre-commit passes every staged file in one invocation, but
# `loophole scan` takes a single path, so scan each file in turn.
# Exit with the worst scanner exit code seen: 1 when a file has
# critical/high findings, 2 on a scanner error, 0 when all files pass.
set -u
ROOT="$(dirname "$0")/.."
status=0
for f in "$@"; do
    "$ROOT/loophole" scan "$f" --no-color
    rc=$?
    if [ "$rc" -gt "$status" ]; then
        status=$rc
    fi
done
exit "$status"
