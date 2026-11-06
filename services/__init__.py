"""
Módulo de Serviços do Lift ERP.
Disponibiliza as interfaces, implementações (Clerk) e fábricas de autenticação.
"""

from services.clerk_auth_service import (
    ClerkAuthenticationService,
    ClerkAuthenticationSession,
)
from services.factories.auth_factory import AuthenticationFactory
from services.interfaces.auth import (
    AuthenticationError,
    AuthenticationServiceInterface,
    AuthenticationSessionInterface,
    AuthContext,
    ForbiddenMetaTagError,
    ForbiddenRuleError,
    InvalidTokenError,
    TokenExpiredError,
    UnauthorizedError,
)

__all__ = [
    # Interfaces e Contextos
    "AuthenticationServiceInterface",
    "AuthenticationSessionInterface",
    "AuthContext",
    # Exceções
    "AuthenticationError",
    "InvalidTokenError",
    "TokenExpiredError",
    "UnauthorizedError",
    "ForbiddenRuleError",
    "ForbiddenMetaTagError",
    # Serviço Clerk
    "ClerkAuthenticationService",
    "ClerkAuthenticationSession",
    # Factory
    "AuthenticationFactory",
]
