"""
Módulo de serviço de autenticação padrão.
Expõe a implementação concreta do Clerk para uso direto.
"""

from services.clerk_auth_service import (
    ClerkAuthenticationService,
    ClerkAuthenticationSession,
)

# Alias para facilitar o uso genérico
AuthenticationService = ClerkAuthenticationService
AuthenticationSession = ClerkAuthenticationSession

__all__ = [
    "ClerkAuthenticationService",
    "ClerkAuthenticationSession",
    "AuthenticationService",
    "AuthenticationSession",
]
