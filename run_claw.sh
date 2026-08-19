#!/bin/bash
# Wrapper script for claw-cli daemon
# Runs in daemonized mode, captures exit code + panic, auto-restarts on crash
# Usage: ./run_claw.sh

LOGDIR="$HOME/.clianywhere"
DAEMON_LOG="$LOGDIR/daemon.log"
EXITLOG="$LOGDIR/exit.log"
CLI="/workspace/tomstore/CodeAnyWhere/daemon_go/claw-cli"

mkdir -p "$LOGDIR"

echo "[$(date -Iseconds)] run_claw.sh started, pid=$$" >> "$EXITLOG"

while true; do
    echo "[$(date -Iseconds)] starting claw-cli (daemonized)..." >> "$EXITLOG"

    # Run as daemonized child directly (skip fork/menu)
    # stdout/stderr from claw already goes to daemon.log via logger,
    # but panic output goes to stderr, so we capture both
    CLIANYWHERE_DAEMONIZED=1 "$CLI" >>"$DAEMON_LOG" 2>>"$EXITLOG"
    EXIT_CODE=$?

    echo "[$(date -Iseconds)] claw-cli exited with code=$EXIT_CODE" >> "$EXITLOG"

    # Exit code 0 = os.Exit(0) from kicked or normal shutdown
    if [ "$EXIT_CODE" -eq 0 ]; then
        echo "[$(date -Iseconds)] exit code 0, restarting in 5s..." >> "$EXITLOG"
        sleep 5
        continue
    fi

    # Signal exit (128+N)
    if [ "$EXIT_CODE" -gt 128 ]; then
        SIG=$((EXIT_CODE - 128))
        echo "[$(date -Iseconds)] killed by signal $SIG, restarting in 5s..." >> "$EXITLOG"
        sleep 5
        continue
    fi

    # Non-zero = panic or other error, restart
    echo "[$(date -Iseconds)] abnormal exit code=$EXIT_CODE, restarting in 5s..." >> "$EXITLOG"
    sleep 5
done
