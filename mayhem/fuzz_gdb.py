#!/usr/bin/env python3
"""Atheris fuzz harness for pygdbmi.

Exercises the GDB Machine-Interface (GDB/MI) response parser on arbitrary
input. Atheris instruments the imported pygdbmi modules (coverage), so
libFuzzer drives the parser toward new code paths.

Run modes (driven by the compiled launcher `pygdbmi_fuzzer` / `-standalone`):
  * fuzzing      - `python3 fuzz_gdb.py [libFuzzer args]`
  * single input - `python3 fuzz_gdb.py <file>` (libFuzzer runs it once)
"""
import signal
import sys

import atheris

import fuzz_helpers

# Instrument ONLY the library under test (scope the include list so import time
# stays low in libFuzzer fork mode - a bare instrument_imports() would pull in
# hundreds of stdlib modules and stall every fork child at startup).
with atheris.instrument_imports(include=["pygdbmi"]):
    from pygdbmi import gdbmiparser
    from pygdbmi.gdbescapes import unescape, advance_past_string_with_gdb_escapes
    from pygdbmi.StringStream import StringStream


# pygdbmi's GDB/MI parser has pathological (super-linear) inputs that run for many
# seconds on a single call. libFuzzer only checks its wall-clock budget BETWEEN
# TestOneInput calls, so one slow call would stall the whole run (and the local
# fuzz-smoke gate, which drives the target with a fixed time budget and no
# per-input -timeout). Guard every call with a SIGALRM so a pathological input
# unwinds quickly instead of hanging the fuzzer; a normal response parses in
# microseconds, so the alarm never fires on real work.
class _InputTimeout(Exception):
    pass


def _on_alarm(signum, frame):
    raise _InputTimeout


signal.signal(signal.SIGALRM, _on_alarm)
_PER_INPUT_TIMEOUT_S = 3


def TestOneInput(data: bytes) -> None:
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    text = fdp.ConsumeRandomString()
    rest = fdp.ConsumeRemainingString()

    signal.setitimer(signal.ITIMER_REAL, _PER_INPUT_TIMEOUT_S)
    try:
        # 1) Core GDB/MI response parser.
        try:
            gdbmiparser.parse_response(text)
        except ValueError:
            # ValueErrors on malformed input (bad quotes/escapes) are expected.
            pass
        except TypeError:
            # parse_response requires a str; a non-str is harness misuse.
            pass

        # 2) The lower-level escape handling + string stream, on the rest.
        try:
            unescape(rest)
        except ValueError:
            pass
        try:
            advance_past_string_with_gdb_escapes(rest)
        except (ValueError, IndexError):
            pass
        try:
            stream = StringStream(rest)
            stream.advance_past_chars(["\n"])
        except (ValueError, IndexError):
            pass
    except _InputTimeout:
        # Pathological-slow input: abandon this unit and let the fuzzer move on.
        pass
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
