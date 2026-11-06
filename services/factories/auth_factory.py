"""
Fábrica de Serviços de Autenticação (AuthenticationFactory)
Lê metadados, headers e flags da requisição e instancia o serviço correspondente
(Clerk por padrão, ou provedores registrados de forma desacoplada).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict, Iterable, Optional, Type

from services.clerk_auth_service import ClerkAuthenticationService
from services.interfaces.auth import (
    AuthenticationServiceInterface,
    AuthenticationSessionInterface,
)

logger = logging.getLogger("services.auth_factory")


class AuthenticationFactory:
    """
    Fábrica responsável por instanciar serviços e sessões de autenticação
    a partir de configurações, flags e metadados de requisições HTTP (FastAPI).
    """

    # Registro de provedores suportados para desacoplamento total
    _providers: Dict[str, Callable[..., AuthenticationServiceInterface]] = {}
    _default_provider: str = "clerk"

    @classmethod
    def register_provider(
        cls,
        name: str,
        factory_fn: Callable[..., AuthenticationServiceInterface],
    ) -> None:
        """Permite registrar novos provedores de autenticação dinamicamente."""
        cls._providers[name.lower()] = factory_fn
        logger.info("Provedor de autenticação registrado: %s", name)

    @classmethod
    def get_service(
        cls,
        provider: Optional[str] = None,
        **kwargs: Any,
    ) -> AuthenticationServiceInterface:
        """
        Instancia o serviço de autenticação correspondente ao provedor informado
        ou configurado nas variáveis de ambiente / flags da aplicação.
        """
        selected = (provider or os.getenv("AUTH_PROVIDER") or cls._default_provider).lower()

        # Provedor Clerk padrão
        if selected == "clerk":
            return ClerkAuthenticationService(
                secret_key=kwargs.get("secret_key"),
                publishable_key=kwargs.get("publishable_key"),
                issuer=kwargs.get("issuer"),
                jwks_url=kwargs.get("jwks_url"),
                allow_dev_tokens=kwargs.get("allow_dev_tokens", True),
            )

        # Provedores registrados via extensão
        if selected in cls._providers:
            return cls._providers[selected](**kwargs)

        raise ValueError(
            f"Provedor de autenticação '{selected}' não suportado. "
            f"Provedores disponíveis: ['clerk', {', '.join(cls._providers.keys())}]"
        )

    @classmethod
    def create_session(
        cls,
        token: Optional[str] = None,
        rules: Optional[Iterable[str]] = None,
        meta_tags: Optional[Dict[str, Any]] = None,
        provider: Optional[str] = None,
        strict: bool = True,
        **service_kwargs: Any,
    ) -> AuthenticationSessionInterface:
        """
        Cria uma sessão de autenticação pronta para ser usada no bloco `with ... as auth:`.
        
        Exemplo:
            with AuthenticationFactory.create_session(token, rules=["Admin"]) as auth:
                if auth.is_authenticated:
                    print(auth.rules)
        """
        service = cls.get_service(provider=provider, **service_kwargs)
        return service.authenticate(
            token=token,
            rules=rules,
            meta_tags=meta_tags,
            strict=strict,
        )

    @classmethod
    def from_request(
        cls,
        request: Any,
        rules: Optional[Iterable[str]] = None,
        meta_tags: Optional[Dict[str, Any]] = None,
        strict: bool = False,
        provider: Optional[str] = None,
    ) -> AuthenticationSessionInterface:
        """
        Lê headers, cookies, metadados e flags da requisição FastAPI e inicia a sessão.
        
        - Lê token Bearer do cabeçalho `Authorization`.
        - Fallback para cookie de sessão do Clerk (`__session`) ou `auth_token`.
        - Captura meta tags automáticas: IP do cliente, User-Agent, Tenant ID (`X-Tenant-ID`).
        - Lê flag de autenticação (`X-Auth-Provider` ou query `auth_provider`).
        """
        headers = getattr(request, "headers", {})
        cookies = getattr(request, "cookies", {})
        client = getattr(request, "client", None)

        # 1. Extração do token: Header Authorization > Cookies Clerk (__session)
        token = headers.get("authorization") or headers.get("Authorization")
        if not token and cookies:
            # Clerk armazena a sessão padrão no cookie '__session'
            cookie_token = cookies.get("__session") or cookies.get("auth_token") or cookies.get("token")
            if cookie_token:
                token = f"Bearer {cookie_token}"

        # 2. Resolução de metadados da requisição
        extracted_meta: Dict[str, Any] = {
            "client_ip": getattr(client, "host", "unknown") if client else "unknown",
            "user_agent": headers.get("user-agent", ""),
            "path": getattr(getattr(request, "url", None), "path", ""),
        }

        # Tenant / Organização informada em cabeçalho ERP
        tenant_id = headers.get("x-tenant-id") or headers.get("X-Tenant-ID")
        if tenant_id:
            extracted_meta["tenant_id"] = tenant_id

        # Flag de autenticação da requisição
        req_provider = (
            provider
            or headers.get("x-auth-provider")
            or headers.get("X-Auth-Provider")
        )

        if meta_tags:
            extracted_meta.update(meta_tags)

        # 3. Instanciação e retorno da sessão
        return cls.create_session(
            token=token,
            rules=rules,
            meta_tags=extracted_meta,
            provider=req_provider,
            strict=strict,
        )
