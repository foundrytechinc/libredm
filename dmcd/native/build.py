#!/usr/bin/env python3
"""Build the LibreDM native extension (crypto + telnet hot paths)."""

import os
import subprocess
import sys
import sysconfig

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.dirname(HERE)
SRC = os.path.join(HERE, "dmcd_native.c")
OUT = os.path.join(HERE, "dmcd_native" + sysconfig.get_config_var("EXT_SUFFIX"))


def main():
    include = sysconfig.get_paths()["include"]
    cc = sysconfig.get_config_var("CC") or "cc"
    cflags = sysconfig.get_config_var("CFLAGS") or ""
    ldflags = sysconfig.get_config_var("LDFLAGS") or ""

    cmd = [
        *cc.split(),
        *cflags.split(),
        "-O2",
        "-fPIC",
        "-shared",
        f"-I{include}",
        SRC,
        "-o",
        OUT,
        *ldflags.split(),
        "-lcrypto",
    ]
    # Drop empty tokens from split flags.
    cmd = [c for c in cmd if c]

    print(" ", " ".join(cmd))
    subprocess.check_call(cmd)
    print(f"built {OUT}")


if __name__ == "__main__":
    main()
