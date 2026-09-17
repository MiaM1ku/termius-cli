# -*- coding: utf-8 -*-
"""Module for application exceptions."""


class TermiusException(Exception):
    """Base exception class."""


class DoesNotExistException(TermiusException):
    """Raise it when model can not be found in storage."""


class TooManyEntriesException(TermiusException):
    """Raise it when there are more models then you think."""


class ArgumentRequiredException(ValueError):
    """Raise it when one of required CLI argument is missed."""


class InvalidArgumentException(ValueError):
    """Raise it when CLI argument have invalid value."""


class SkipField(TermiusException):
    """Raise it when needs to skip field."""


class OptionNotSetException(TermiusException):
    """Raise it when no option in section."""


class AuthyTokenIssue(TermiusException):
    """Raise it when API error caused by `authy_token`."""


class OutdatedVersion(TermiusException):
    """Raise it when API error caused by 490 HTTP status code."""


class NotMigratedError(TermiusException):
    """Raise it when the account uses the SRP/gRPC login path."""


class OtpTokenRequired(TermiusException):
    """Raise it when login requires an OTP/Authy token."""


class ApiError(TermiusException):
    """Raise it when a Termius Cloud request fails."""

    def __init__(self, message, status=None, payload=None):
        super(ApiError, self).__init__(message)
        self.status = status
        self.payload = payload
