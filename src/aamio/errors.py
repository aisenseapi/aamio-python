"""Errors that carry the code the three runtimes give the same failure.

error_code on the command line and over MCP is this code, the same in
aamio-python, aamio-php and the Node runtime: unknown_channel, never the name
of a class. An error without one is said by the name of its class, as before
(a check of 13 November 2026).
"""


class CodedValueError(ValueError):
    """What was given is wrong, with the code the other two runtimes give it."""

    def __init__(self, code, message):
        super().__init__(message)
        self.error_code = code


class CodedLookupError(LookupError):
    """What was asked for is not there, with the code the other two runtimes give it."""

    def __init__(self, code, message):
        super().__init__(message)
        self.error_code = code


class CodedRuntimeError(RuntimeError):
    """What could not be done, with the code the other two runtimes give it."""

    def __init__(self, code, message):
        super().__init__(message)
        self.error_code = code


def code_of(error):
    """The code of an error, or the name of its class when it has none."""
    code = getattr(error, "error_code", None)
    return code if isinstance(code, str) and code else error.__class__.__name__
