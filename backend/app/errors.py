class ProviderError(Exception):
    """Base class for failures reported by an upstream intelligence provider.

    Attributes:
        status_code: The HTTP status the API should return to its own caller.
        provider: Human-readable name of the provider that failed.
    """

    status_code = 502

    def __init__(self, message: str, provider: str = "provider") -> None:
        super().__init__(message)
        self.provider = provider


class ProviderNotConfigured(ProviderError):
    """Raised when a lookup needs a credential that was never supplied."""

    status_code = 503


class ProviderAuthError(ProviderError):
    """Raised when a provider rejects the configured credential."""

    status_code = 502


class IndicatorNotFound(ProviderError):
    """Raised when a provider holds no record of the requested indicator."""

    status_code = 404


class ProviderQuotaExceeded(ProviderError):
    """Raised when a provider's rate limit or daily quota is exhausted."""

    status_code = 429


class ProviderUnavailable(ProviderError):
    """Raised when a provider is unreachable or returns an unexpected status."""

    status_code = 502
