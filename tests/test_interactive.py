#!/usr/bin/env python3
"""PTY tests for interactive passphrase input and signal handling."""

import os
import pty
import select
import signal
import subprocess
import sys
import time


def read_until(fd, process, needle, timeout=5.0):
    output = b""
    deadline = time.monotonic() + timeout
    while needle not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("timed out waiting for prompt")
        readable, _, _ = select.select([fd], [], [], remaining)
        if not readable:
            if process.poll() is not None:
                break
            continue
        try:
            chunk = os.read(fd, 1024)
        except OSError:
            break
        if not chunk:
            break
        output += chunk
    return output


def finish(fd, process, output, timeout=5.0):
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
    return process.wait(timeout=timeout), output


def start(binary, args):
    master, slave = pty.openpty()
    process = subprocess.Popen(
        [binary] + args,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
    )
    os.close(slave)
    return master, process


def test_hidden_input(binary):
    master, process = start(binary, ["test@example.org"])
    try:
        output = read_until(master, process, b"Passphrase: ")
        os.write(master, b"too short\n")
        status, output = finish(master, process, output)
        assert status == 1, status
        assert b"invalid passphrase" in output, output
        assert b"too short" not in output, output
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)


def test_signal(binary):
    master, process = start(binary, ["test@example.org"])
    try:
        output = read_until(master, process, b"Passphrase: ")
        time.sleep(0.1)
        os.kill(process.pid, signal.SIGINT)
        status, output = finish(master, process, output)
        assert status == -signal.SIGINT, (status, output)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)


if __name__ == "__main__":
    binary = sys.argv[1] if len(sys.argv) > 1 else "build/pass2key"
    test_hidden_input(binary)
    test_signal(binary)
