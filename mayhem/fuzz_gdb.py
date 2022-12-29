#!/usr/bin/env python3

import atheris
import sys
import fuzz_helpers
import random

with atheris.instrument_imports():
    from pygdbmi import gdbmiparser

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)

    try:
        gdbmiparser.parse_response(fdp.ConsumeRandomString())
    except ValueError as e:
        if "Missing closing quote" in str(e) or "Invalid escape" in str(e):
            return -1
        raise
    except TypeError:
        if random.random() > 0.99:
            raise
        return -1
def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
