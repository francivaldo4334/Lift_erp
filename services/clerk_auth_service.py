"""
Implementação do Serviço de Autenticação para Clerk (ClerkAuthenticationService).
Implementa `AuthenticationServiceInterface` e o context manager `AuthenticationSession`
para integração com Clerk (https://clerk.com) em aplicações FastAPI / Jinja.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from types import TracebackType
from typing import Any, Dict, Iterable, Optional, Set, Type

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

logger = logging.getLogger("services.clerk_auth")


# ============================================================================
# Sessão de Autenticação para Clerk (Context Manager)
# ============================================================================

class ClerkAuthenticationSession(AuthenticationSessionInterface):
    """
    Sessão de autenticação gerenciada por bloco de contexto Python (`with ... as auth:`).
    
    Exemplo:
        with clerk_service.authenticate(token="Bearer ...", rules=["Admin"]) as auth:
            if auth.is_authenticated:
                print(f"Bem-vindo {auth.username}, regras: {auth.rules}")
                
        async with clerk_service.authenticate(token=request.headers.get("Authorization")) as auth:
            auth.require_rule("Admin")
    """

    def __init__(
        self,
        service: AuthenticationServiceInterface,
        token: Optional[str] = None,
        rules: Optional[Iterable[str]] = None,
        meta_tags: Optional[Dict[str, Any]] = None,
        strict: bool = True,
    ) -> None:
        self._service = service
        self._raw_token = token
        self._required_rules = set(rules) if rules else set()
        self._meta_tags = dict(meta_tags) if meta_tags else {}
        self._strict = strict
        self._context: Optional[AuthContext] = None

    def __enter__(self) -> AuthContext:
        """Executa a resolução e validação do token Clerk ao entrar no bloco `with`."""
        self._context = self._resolve_authentication()
        return self._context

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Optional[bool]:
        """Finalização segura da sessão de autenticação."""
        if self._context:
            logger.debug(
                "Sessão Clerk encerrada para user=%s (auth=%s)",
                self._context.username,
                self._context.is_authenticated,
            )
        return False

    async def __aenter__(self) -> AuthContext:
        """Suporte para `async with clerk_service.authenticate(...) as auth:`."""
        return self.__enter__()

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Optional[bool]:
        """Finalização assíncrona da sessão."""
        return self.__exit__(exc_type, exc_val, exc_tb)

    def _resolve_authentication(self) -> AuthContext:
        """Extrai o token Bearer, valida no Clerk e monta o AuthContext com regras e meta tags."""
        clean_token = self._service.extract_bearer_token(self._raw_token)

        if not clean_token:
            if self._strict:
                raise UnauthorizedError("Token de autorização Bearer (Clerk) não fornecido.")
            return AuthContext(is_authenticated=False)

        try:
            payload = self._service.validate_token(clean_token)
            context = self._service.create_context(
                payload=payload,
                token=clean_token,
                meta_tags=self._meta_tags,
            )

            # Validar se as regras requeridas estão satisfeitas
            for req_rule in self._required_rules:
                if not context.has_rule(req_rule):
                    if self._strict:
                        raise ForbiddenRuleError(
                            req_rule,
                            f"Usuário '{context.username}' não possui a regra exigida: '{req_rule}'.",
                        )
                    context.is_authenticated = False

            return context

        except AuthenticationError:
            if self._strict:
                raise
            return AuthContext(is_authenticated=False)
        except Exception as exc:
            logger.exception("Falha na validação do token Clerk: %s", exc)
            if self._strict:
                raise InvalidTokenError(f"Falha ao validar credencial Clerk: {str(exc)}") from exc
            return AuthContext(is_authenticated=False)


# ============================================================================
# Serviço de Autenticação Clerk (ClerkAuthenticationService)
# ============================================================================

class ClerkAuthenticationService(AuthenticationServiceInterface):
    """
    Serviço de autenticação integrado ao Clerk (https://clerk.com).
    
    Características:
    - Extração resiliente de tokens Bearer do cabeçalho HTTP Authorization.
    - Decodificação e validação de claims emitidas pelo Clerk (sub, exp, nbf, iss, etc.).
    - Suporte a Organizations e Roles nativas do Clerk (`org_id`, `org_role`, `org_slug`, `org_permissions`).
    - Extração automática de metadados (`public_metadata`, `metadata`) mapeando regras e meta tags.
    - Modo de desenvolvimento / mock para testes locais de ERP sem necessidade de credenciais de produção.
    """

    BEARER_PATTERN = re.compile(r"^Bearer\s+(.+)$", re.IGNORECASE)

    def __init__(
        self,
        secret_key: Optional[str] = None,
        publishable_key: Optional[str] = None,
        issuer: Optional[str] = None,
        jwks_url: Optional[str] = None,
        allow_dev_tokens: bool = True,
    ) -> None:
        """
        :param secret_key: Chave secreta do Clerk (CLERK_SECRET_KEY, formato: 'sk_test_...' ou 'sk_live_...').
        :param publishable_key: Chave pública do Clerk (CLERK_PUBLISHABLE_KEY, formato: 'pk_test_...').
        :param issuer: URL do emissor Clerk (ex: 'https://clerk.meuapp.com' ou 'https://foo.clerk.accounts.dev').
        :param jwks_url: URL para obtenção do JWKS para validação de chave pública.
        :param allow_dev_tokens: Se True, aceita tokens 'dev-clerk-...' para desenvolvimento local no ERP.
        """
        self.secret_key = secret_key or os.getenv("CLERK_SECRET_KEY")
        self.publishable_key = publishable_key or os.getenv("CLERK_PUBLISHABLE_KEY")
        self.issuer = issuer or os.getenv("CLERK_ISSUER")
        self.jwks_url = jwks_url or os.getenv("CLERK_JWKS_URL")
        self.allow_dev_tokens = allow_dev_tokens

    def extract_bearer_token(self, authorization_header: Optional[str]) -> Optional[str]:
        """
        Extrai o token limpo de strings como 'Bearer eyJhbGciOi...',
        removendo o prefixo e espaços. Aceita também o token puro.
        """
        if not authorization_header:
            return None

        clean = authorization_header.strip()
        match = self.BEARER_PATTERN.match(clean)
        if match:
            return match.group(1).strip()

        if clean:
            return clean

        return None

    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Valida a credencial e decodifica o token de sessão do Clerk.
        Retorna o dicionário com o payload de claims do usuário.
        """
        if not token:
            raise InvalidTokenError("O token fornecido está vazio.")

        # 1. Suporte a tokens locais de teste para desenvolvimento rápido do ERP
        if self.allow_dev_tokens and token.startswith("dev-clerk-"):
            return self._decode_dev_clerk_token(token)

        # 2. Decodificação de JWT do Clerk (Header.Payload.Signature)
        parts = token.split(".")
        if len(parts) == 3:
            payload = self._decode_clerk_jwt(parts)
            self._verify_claims(payload)
            return payload

        # 3. Payload direto codificado em base64 (mock ou teste)
        if len(parts) == 1:
            try:
                raw_json = self._base64_url_decode(parts[0]).decode("utf-8")
                payload = json.loads(raw_json)
                self._verify_claims(payload)
                return payload
            except Exception:
                pass

        raise InvalidTokenError("Formato de token Clerk inválido ou não reconhecido.")

    def create_context(
        self,
        payload: Dict[str, Any],
        token: Optional[str] = None,
        rules: Optional[Iterable[str]] = None,
        meta_tags: Optional[Dict[str, Any]] = None,
    ) -> AuthContext:
        """
        Mapeia os claims do Clerk em um AuthContext fortemente tipado.
        
        Extrai:
        - user_id (Clerk `sub`, ex: 'user_2xyz...')
        - username (Clerk `name`, `username`, `first_name` ou email)
        - email (Clerk `email` ou `primary_email_address`)
        - rules (Clerk `org_role`, `org_permissions`, `public_metadata.rule` / `roles`)
        - meta_tags (Clerk `org_id`, `org_slug`, `sid`, `auth_provider='clerk'`)
        """
        user_id = payload.get("sub") or payload.get("id") or payload.get("user_id")
        
        # Identificação de nome do usuário
        username = (
            payload.get("name")
            or payload.get("username")
            or payload.get("first_name")
            or payload.get("user")
            or str(user_id or "ClerkUser")
        )
        email = payload.get("email") or payload.get("email_address")

        # 1. Extração de Regras (Rules / Roles) do Clerk
        user_rules: Set[str] = set()

        # Extrair role de organização do Clerk (ex: 'org:admin' -> 'org:admin', 'Admin')
        org_role = payload.get("org_role")
        if org_role and isinstance(org_role, str):
            user_rules.add(org_role)
            # Adicionar forma simplificada (ex: 'org:admin' -> 'Admin', 'admin')
            clean_role = org_role.split(":")[-1].capitalize()
            user_rules.add(clean_role)

        # Extrair permissões de organização do Clerk
        org_permissions = payload.get("org_permissions")
        if isinstance(org_permissions, list):
            user_rules.update(str(p) for p in org_permissions)

        # Extrair regras personalizadas do public_metadata do Clerk
        public_meta = payload.get("public_metadata") or payload.get("metadata") or {}
        if isinstance(public_meta, dict):
            rule_entry = public_meta.get("rule") or public_meta.get("rules") or public_meta.get("roles")
            if isinstance(rule_entry, str):
                user_rules.add(rule_entry)
            elif isinstance(rule_entry, (list, tuple, set)):
                user_rules.update(str(r) for r in rule_entry)

        # Regras raiz no payload
        root_rules = payload.get("rules") or payload.get("rule")
        if isinstance(root_rules, str):
            user_rules.add(root_rules)
        elif isinstance(root_rules, (list, tuple, set)):
            user_rules.update(str(r) for r in root_rules)

        # Mesclar regras explícitas passadas na chamada
        if rules:
            user_rules.update(rules)

        # 2. Extração de Meta Tags do Clerk
        combined_meta: Dict[str, Any] = {
            "auth_provider": "clerk",
            "session_id": payload.get("sid"),
            "org_id": payload.get("org_id"),
            "org_slug": payload.get("org_slug"),
            "authorized_party": payload.get("azp"),
            "auth_time": payload.get("iat") or int(time.time()),
        }

        # Metadados adicionais do Clerk public_metadata
        if isinstance(public_meta, dict):
            for k, v in public_meta.items():
                if k not in ("rule", "rules", "roles"):
                    combined_meta[k] = v

        # Mesclar meta tags explícitas passadas na sessão
        if meta_tags:
            combined_meta.update(meta_tags)

        return AuthContext(
            is_authenticated=True,
            user_id=user_id,
            username=username,
            email=email,
            token=token,
            rules=user_rules,
            meta_tags=combined_meta,
            payload=payload,
        )

    def authenticate(
        self,
        token: Optional[str] = None,
        rules: Optional[Iterable[str]] = None,
        meta_tags: Optional[Dict[str, Any]] = None,
        strict: bool = True,
    ) -> ClerkAuthenticationSession:
        """
        Inicia uma sessão de autenticação do Clerk compatível com `with ... as auth:`.
        """
        return ClerkAuthenticationSession(
            service=self,
            token=token,
            rules=rules,
            meta_tags=meta_tags,
            strict=strict,
        )

    # ------------------------------------------------------------------------
    # Métodos Internos de Validação e Decodificação do Clerk
    # ------------------------------------------------------------------------

    def _decode_clerk_jwt(self, parts: list[str]) -> Dict[str, Any]:
        """Decodifica as partes do JWT gerado pelo Clerk."""
        _header_b64, payload_b64, _signature_b64 = parts

        try:
            payload_json = self._base64_url_decode(payload_b64).decode("utf-8")
            payload = json.loads(payload_json)
        except Exception as exc:
            raise InvalidTokenError("Corpo do token JWT Clerk corrompido.") from exc

        return payload

    def _decode_dev_clerk_token(self, token: str) -> Dict[str, Any]:
        """
        Token de desenvolvimento: 'dev-clerk-<username>-<rule>-<org>'
        Exemplos:
          - 'dev-clerk-janja-Admin-lift'
          - 'dev-clerk-luisInacio-Dev'
        """
        parts = token.split("-")
        username = parts[2] if len(parts) > 2 else "clerk_user"
        rule = parts[3] if len(parts) > 3 else "Admin"
        org_slug = parts[4] if len(parts) > 4 else "lift-erp"

        return {
            "sub": f"user_clerk_{username}",
            "name": username,
            "email": f"{username.lower()}@lift.local",
            "sid": f"sess_{int(time.time())}",
            "org_id": f"org_{org_slug}",
            "org_slug": org_slug,
            "org_role": f"org:{rule.lower()}",
            "public_metadata": {
                "rule": rule,
                "department": "ERP Core",
            },
            "iss": self.issuer or "https://clerk.lift.local",
            "exp": int(time.time()) + 86400,
        }

    def _verify_claims(self, payload: Dict[str, Any]) -> None:
        """Valida claims temporais e emissor do Clerk."""
        # 1. Expiração
        exp = payload.get("exp")
        if exp is not None and isinstance(exp, (int, float)):
            if time.time() > exp:
                raise TokenExpiredError("A sessão do Clerk expirou.")

        # 2. Not before
        nbf = payload.get("nbf")
        if nbf is not None and isinstance(nbf, (int, float)):
            if time.time() < nbf:
                raise InvalidTokenError("O token do Clerk ainda não é válido (nbf).")

        # 3. Validação de Issuer (se configurado)
        if self.issuer and payload.get("iss"):
            if payload.get("iss") != self.issuer:
                raise InvalidTokenError(
                    f"Emissor (iss) do Clerk incompatível. Esperado: {self.issuer}, Recebido: {payload.get('iss')}"
                )

    @staticmethod
    def _base64_url_decode(data: str) -> bytes:
        padded = data + "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(padded)
