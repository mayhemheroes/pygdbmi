#!/usr/bin/env python3

import atheris
import sys
import fuzz_helpers

with atheris.instrument_imports():
    from pygdbmi import gdbmiparser

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)

    try:
        gdbmiparser.parse_response(fdp.ConsumeRandomString())
    except (TypeError, ValueError):
        return -1
def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
