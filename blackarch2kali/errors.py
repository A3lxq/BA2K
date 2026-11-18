"""Exception hierarchy."""


class BA2KError(Exception):
    """Base error."""


class ConfigError(BA2KError):
    pass


class UnsafeInputError(BA2KError):
    """Input rejected by a safety validator."""


class CollectorError(BA2KError):
    pass


class RateLimitError(CollectorError):
    def __init__(self, message: str, reset_at: float | None = None) -> None:
        super().__init__(message)
        self.reset_at = reset_at


class DatabaseError(BA2KError):
    pass


class InstallError(BA2KError):
    pass
