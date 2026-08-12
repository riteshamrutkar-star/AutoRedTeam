"""Domain exceptions for OpenAPI parsing, validation, and normalization."""


class OpenAPIException(Exception):
    """Base exception for OpenAPI processing errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class InvalidFileFormatError(OpenAPIException):
    """Raised when the uploaded file format is unsupported or invalid JSON/YAML."""

    pass


class OpenAPIValidationError(OpenAPIException):
    """Raised when the specification fails structural OpenAPI validation."""

    pass


class UnsupportedSpecVersionError(OpenAPIException):
    """Raised when the specification version is not OpenAPI 3.x (e.g. Swagger 2.0)."""

    pass


class ReferenceResolutionError(OpenAPIException):
    """Raised when a local $ref pointer cannot be resolved."""

    pass
