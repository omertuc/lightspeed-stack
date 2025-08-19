"""Authorization engine for role evaluation and access control."""

from abc import ABC, abstractmethod
import json
import logging
from typing import Any, FrozenSet

from jsonpath_ng import parse

from auth.interface import AuthTuple
from models.config import JwtRoleRule, AccessRule, JsonPathOperator, Action

logger = logging.getLogger(__name__)


UserRoles = FrozenSet[str]


class AccessResolver(ABC):  # pylint: disable=too-few-public-methods
    """Base class for all access resolution strategies."""

    @abstractmethod
    async def check_access(self, action: Action, user_roles: UserRoles) -> bool:
        """Check if the user has access to the specified action based on their roles."""


class NoopAccessResolver(AccessResolver):  # pylint: disable=too-few-public-methods
    """No-op access resolver that does not perform any access checks."""

    async def check_access(self, action: Action, user_roles: UserRoles) -> bool:
        """Return True always, indicating access is granted."""
        _ = action  # Unused
        _ = user_roles  # Unused
        return True


class RoleResolutionError(Exception):
    """Custom exception for role resolution errors."""


class RolesResolver(ABC):  # pylint: disable=too-few-public-methods
    """Base class for all role resolution strategies."""

    @abstractmethod
    async def resolve_roles(self, auth: AuthTuple) -> UserRoles:
        """Given an auth tuple, return the list of user roles."""


class NoopRolesResolver(RolesResolver):  # pylint: disable=too-few-public-methods
    """No-op roles resolver that does not perform any role resolution."""

    async def resolve_roles(self, auth: AuthTuple) -> UserRoles:
        """Return an empty list of roles."""
        _ = auth  # Unused
        return frozenset()


class JwtRolesResolver(RolesResolver):  # pylint: disable=too-few-public-methods
    """Engine for extract roles from JWT claims using JSONPath rules."""

    def __init__(self, role_rules: list[JwtRoleRule]):
        """Initialize the authorization engine.

        Args:
            role_rules: Rules for extracting roles from JWT claims
        """
        self.role_rules = role_rules

    async def resolve_roles(self, auth: AuthTuple) -> UserRoles:
        """Extract roles from JWT claims using configured rules."""
        jwt_claims = self._get_claims(auth)
        return frozenset(
            role
            for rule in self.role_rules
            for role in self.evaluate_role_rules(rule, jwt_claims)
        )

    @staticmethod
    def evaluate_role_rules(rule: JwtRoleRule, jwt_claims: dict[str, Any]) -> UserRoles:
        """Get roles from a JWT role rule if it matches the claims."""
        return (
            frozenset(rule.roles)
            if JwtRolesResolver._evaluate_operator(
                rule.negate,
                [match.value for match in parse(rule.jsonpath).find(jwt_claims)],
                rule.operator,
                rule.value,
            )
            else frozenset()
        )

    @staticmethod
    def _get_claims(auth: AuthTuple) -> dict[str, Any]:
        """Get the JWT claims from the auth tuple."""
        _, _, token = auth
        jwt_claims = json.loads(token)

        if not jwt_claims:
            raise RoleResolutionError(
                "Invalid authentication token: no JWT claims found"
            )

        return jwt_claims

    @staticmethod
    def _evaluate_operator(
        negate: bool, match: Any, operator: JsonPathOperator, value: Any
    ) -> bool:  # pylint: disable=too-many-branches
        """Evaluate an operator against a match and value."""
        result = False
        match operator:
            case JsonPathOperator.EQUALS:
                result = match == value
            case JsonPathOperator.CONTAINS:
                result = value in match
            case JsonPathOperator.IN:
                result = match in value

        if negate:
            result = not result

        return result


class GenericAccessResolver(AccessResolver):  # pylint: disable=too-few-public-methods
    """General role-based access control engine, should apply with most authentication methods."""

    def __init__(self, access_rules: list[AccessRule]):
        """Initialize the access resolver with access rules."""
        for rule in access_rules:
            # Since this is nonsensical, it might be a mistake, so hard fail
            if Action.ADMIN in rule.actions and len(rule.actions) > 1:
                raise ValueError(
                    "Access rule with 'admin' action cannot have other actions"
                )

        self.access_rules = access_rules

        # Build a lookup table for access rules
        self._access_lookup: dict[str, set[Action]] = {}
        for rule in access_rules:
            if rule.role not in self._access_lookup:
                self._access_lookup[rule.role] = set()
            self._access_lookup[rule.role].update(rule.actions)

    async def check_access(self, action: Action, user_roles: UserRoles) -> bool:
        """Check if the user has access to the specified action based on their roles."""
        if action != Action.ADMIN and self.check_access(action.ADMIN, user_roles):
            # Recurse to check if the roles allow the user to perform the admin action,
            # if they do, then we allow any action
            return True

        for role in user_roles:
            if role in self._access_lookup and action in self._access_lookup[role]:
                logger.debug(
                    "Access granted: role '%s' can perform action '%s'", role, action
                )
                return True

        logger.debug(
            "Access denied: roles %s cannot perform action '%s'", user_roles, action
        )
        return False
