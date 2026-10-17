"""Registro e exportação das regras SAST."""
from typing import List, Type
from .base_rule import BaseRule
from .eval_exec_rule import DangerousEvalRule
from .secrets_rule import HardcodedSecretsRule
from .command_inj_rule import CommandInjectionRule
from .taint_rule import TaintAnalysisRule
from .ssrf_rule import ServerSideRequestForgeryRule

DEFAULT_RULES: List[Type[BaseRule]] = [
    DangerousEvalRule,
    HardcodedSecretsRule,
    CommandInjectionRule,
    TaintAnalysisRule,
    ServerSideRequestForgeryRule,
]

__all__ = [
    "BaseRule",
    "DangerousEvalRule",
    "HardcodedSecretsRule",
    "CommandInjectionRule",
    "TaintAnalysisRule",
    "ServerSideRequestForgeryRule",
    "DEFAULT_RULES",
]
