"""
Interface de Autenticação - Camada de Serviços (Services Layer)
Define contratos abstratos, contextos e exceções para garantir desacoplamento
conforme o princípio de Inversão de Dependência (DIP).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Dict, Iterable, Optional, Set, Type


# ============================================================================
# Exceções de Domínio de Autenticação
# ============================================================================

class AuthenticationError(Exception):
    """Exceção base para erros ocorridos durante o fluxo de autenticação."""
    def __init__(self, message: str = "Falha na autenticação.", code: str = "AUTH_ERROR") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class InvalidTokenError(AuthenticationError):
    """Lançada quando o token Bearer fornecido é inválido, corrompido ou malformado."""
    def __init__(self, message: str = "Token Bearer inválido ou malformado.") -> None:
        super().__init__(message=message, code="INVALID_TOKEN")


class TokenExpiredError(AuthenticationError):
    """Lançada quando o token de autenticação expirou."""
    def __init__(self, message: str = "Token de autenticação expirado.") -> None:
        super().__init__(message=message, code="TOKEN_EXPIRED")


class UnauthorizedError(AuthenticationError):
    """Lançada quando a requisição não possui credenciais válidas ou sessão ativa."""
    def __init__(self, message: str = "Acesso não autorizado. Credenciais ausentes ou inválidas.") -> None:
        super().__init__(message=message, code="UNAUTHORIZED")


class ForbiddenRuleError(AuthenticationError):
    """Lançada quando o usuário autenticado não possui as regras (rules/roles) exigidas."""
    def __init__(self, rule: str, message: Optional[str] = None) -> None:
        detail = message or f"Acesso negado: a regra '{rule}' é necessária para esta operação."
        super().__init__(message=detail, code="FORBIDDEN_RULE")
        self.rule = rule


class ForbiddenMetaTagError(AuthenticationError):
    """Lançada quando o contexto de autenticação não atende a uma meta tag exigida."""
    def __init__(self, key: str, expected: Any, message: Optional[str] = None) -> None:
        detail = message or f"Acesso negado: meta tag '{key}' esperada='{expected}' não foi atendida."
        super().__init__(message=detail, code="FORBIDDEN_META_TAG")
        self.key = key
        self.expected = expected


# ============================================================================
# Contexto de Autenticação (AuthContext)
# ============================================================================

@dataclass
class AuthContext:
    """
    Contexto representativo de uma sessão de autenticação.
    
    Disponibilizado dentro do bloco `with ... as auth:` contendo:
    - `is_authenticated`: flag booleana de estado de autenticação.
    - `rules`: conjunto de regras/permissões/papéis do usuário.
    - `meta_tags`: dicionário de metadados associados à requisição/autenticação.
    - `user_id` e `username`: identificação do usuário.
    - `payload`: dados brutos extraídos do token.
    - `token`: token bruto recebido.
    """
    is_authenticated: bool = False
    user_id: Optional[str | int] = None
    username: Optional[str] = None
    email: Optional[str] = None
    token: Optional[str] = None
    rules: Set[str] = field(default_factory=set)
    meta_tags: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)

    def has_rule(self, rule: str) -> bool:
        """Verifica se a sessão possui a regra especificada (case-insensitive)."""
        rule_lower = rule.strip().lower()
        return any(r.strip().lower() == rule_lower for r in self.rules)

    def has_all_rules(self, *rules: str) -> bool:
        """Verifica se a sessão atende a todas as regras fornecidas."""
        return all(self.has_rule(r) for r in rules)

    def has_any_rule(self, *rules: str) -> bool:
        """Verifica se a sessão possui pelo menos uma das regras fornecidas."""
        return any(self.has_rule(r) for r in rules)

    def require_rule(self, rule: str) -> None:
        """
        Assegura que a sessão possui a regra exigida.
        Lança `ForbiddenRuleError` caso a regra não esteja presente.
        """
        if not self.is_authenticated:
            raise UnauthorizedError("Usuário não autenticado ao verificar regra.")
        if not self.has_rule(rule):
            raise ForbiddenRuleError(rule)

    def has_meta_tag(self, key: str, expected_value: Any = None) -> bool:
        """
        Verifica se a meta tag existe e, opcionalmente, se possui o valor esperado.
        """
        if key not in self.meta_tags:
            return False
        if expected_value is not None:
            return self.meta_tags[key] == expected_value
        return True

    def require_meta_tag(self, key: str, expected_value: Any = None) -> None:
        """
        Assegura que uma meta tag existe e corresponde ao valor esperado.
        Lança `ForbiddenMetaTagError` se a verificação falhar.
        """
        if not self.is_authenticated:
            raise UnauthorizedError("Usuário não autenticado ao verificar meta tag.")
        if not self.has_meta_tag(key, expected_value):
            raise ForbiddenMetaTagError(key, expected_value)

    def to_dict(self) -> Dict[str, Any]:
        """Converte o contexto em dicionário pronto para uso em templates Jinja."""
        return {
            "is_authenticated": self.is_authenticated,
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "rules": list(self.rules),
            "meta_tags": self.meta_tags,
            "token": self.token,
        }


# ============================================================================
# Interface da Sessão de Autenticação (Context Manager)
# ============================================================================

class AuthenticationSessionInterface(ABC):
    """
    Interface para sessões gerenciadas por contexto (Python `with` e `async with`).
    
    Exemplo de uso:
        with service.authenticate(token="Bearer xyz") as auth:
            if auth.is_authenticated:
                auth.require_rule("Admin")
                ...
    """

    @abstractmethod
    def __enter__(self) -> AuthContext:
        """Inicializa o contexto e retorna o AuthContext para o bloco `as auth`."""
        pass

    @abstractmethod
    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Optional[bool]:
        """Finaliza a sessão com segurança ao sair do bloco `with`."""
        pass

    @abstractmethod
    async def __aenter__(self) -> AuthContext:
        """Versão assíncrona para suporte a `async with ... as auth:` em rotas FastAPI."""
        pass

    @abstractmethod
    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Optional[bool]:
        """Finalização assíncrona da sessão ao sair do bloco `async with`."""
        pass


# ============================================================================
# Interface Principal do Serviço de Autenticação
# ============================================================================

class AuthenticationServiceInterface(ABC):
    """
    Contrato abstrato para serviços de autenticação por token.
    Desacopla a aplicação do mecanismo concreto (JWT, OAuth2, Mock, Database).
    """

    @abstractmethod
    def extract_bearer_token(self, authorization_header: Optional[str]) -> Optional[str]:
        """
        Extrai o token limpo do cabeçalho Authorization ou string Bearer.
        Ex: 'Bearer eyJhbGciOi...' -> 'eyJhbGciOi...'
        """
        pass

    @abstractmethod
    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Valida a integridade, assinatura e validade do token.
        Retorna o dicionário com os claims/payload decodificado.
        Lança `InvalidTokenError` ou `TokenExpiredError` se inválido.
        """
        pass

    @abstractmethod
    def authenticate(
        self,
        token: Optional[str] = None,
        rules: Optional[Iterable[str]] = None,
        meta_tags: Optional[Dict[str, Any]] = None,
        strict: bool = True,
    ) -> AuthenticationSessionInterface:
        """
        Inicia uma sessão de autenticação compatível com sintaxe de bloco `with`.
        
        :param token: Token Bearer recebido (cru ou prefixado com 'Bearer ').
        :param rules: Regras/papéis adicionais requeridos ou atribuídos à sessão.
        :param meta_tags: Metadados da requisição/sessão (ex: tenant_id, ip, device).
        :param strict: Se True, lança exceções de autenticação ao entrar no bloco `with`.
                       Se False, define `auth.is_authenticated = False` sem quebrar a execução.
        :return: Uma instância de `AuthenticationSessionInterface`.
        """
        pass

    @abstractmethod
    def create_context(
        self,
        payload: Dict[str, Any],
        token: Optional[str] = None,
        rules: Optional[Iterable[str]] = None,
        meta_tags: Optional[Dict[str, Any]] = None,
    ) -> AuthContext:
        """
        Monta um objeto `AuthContext` fortemente tipado a partir do payload validado.
        """
        pass
