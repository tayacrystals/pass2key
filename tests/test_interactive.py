#!/usr/bin/env python3
"""PTY tests for interactive passphrase input and signal handling.

The passphrase prompt is printed only after echo is disabled, so reaching the
prompt is a deterministic synchronisation point: no sleeps are needed.
"""

import os
import pty
import select
import signal
import subprocess
import sys
import termios


def read_until(fd, process, needle, timeout=5.0):
    output = b""
    deadline = timeout
    while needle not in output:
        readable, _, _ = select.select([fd], [], [], deadline)
        if not readable:
            if process.poll() is not None:
                break
            raise AssertionError(
                "timed out waiting for %r; got %r" % (needle, output)
            )
        try:
            chunk = os.read(fd, 1024)
        except OSError:
            break
        if not chunk:
            break
        output += chunk
        deadline = timeout
    return output


def drain(fd, process, output, timeout=5.0):
    while True:
        readable, _, _ = select.select([fd], [], [], timeout)
        if not readable:
            break
        try:
            chunk = os.read(fd, 1024)
        except OSError:
            break
        if not chunk:
            break
        output += chunk
    return output


def start(binary, args):
    master, slave = pty.openpty()
    process = subprocess.Popen(
        [binary] + args,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
    )
    return master, slave, process


def test_hidden_input(binary):
    master, slave, process = start(binary, ["test@example.org"])
    try:
        output = read_until(master, process, b"Passphrase: ")
        attributes = termios.tcgetattr(slave)
        assert not attributes[3] & termios.ECHO, "echo still on at the prompt"
        # Closing the slave lets the master report EOF/EIO when the child exits.
        os.close(slave)
        slave = -1
        os.write(master, b"too short\n")
        output = drain(master, process, output)
        status = process.wait(timeout=5)
        assert status == 1, (status, output)
        assert b"invalid passphrase" in output, output
        assert b"too short" not in output, output
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        if slave >= 0:
            os.close(slave)


def test_signal_restores_terminal(binary):
    master, slave, process = start(binary, ["test@example.org"])
    try:
        read_until(master, process, b"Passphrase: ")
        assert not termios.tcgetattr(slave)[3] & termios.ECHO, "echo still on"
        os.kill(process.pid, signal.SIGINT)
        status = process.wait(timeout=5)
        assert status == -signal.SIGINT, status
        # The handler restores the terminal before re-raising the signal, so
        # this also proves the handler ran instead of the default action.
        assert termios.tcgetattr(slave)[3] & termios.ECHO, "echo not restored"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        os.close(slave)


def test_stdin_from_pipe(binary):
    process = subprocess.run(
        [binary, "a@b"],
        input=b"one two three\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    assert process.returncode == 1, process.returncode
    assert b"reading passphrase from standard input" in process.stderr
    assert b"Passphrase: " not in process.stderr, process.stderr
    assert process.stdout == b"", process.stdout


if __name__ == "__main__":
    binary = sys.argv[1] if len(sys.argv) > 1 else "build/pass2key"
    test_hidden_input(binary)
    test_signal_restores_terminal(binary)
    test_stdin_from_pipe(binary)
    print("test_interactive: ok")
