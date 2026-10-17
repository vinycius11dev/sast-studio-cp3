"""Módulo de analisadores multi-linguagem (Python, JavaScript, Java)."""
from .base import LanguageScanner
from .python_scanner import PythonScanner
from .javascript_scanner import JavaScriptScanner
from .java_scanner import JavaScanner

SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".java": "java",
}

__all__ = [
    "LanguageScanner",
    "PythonScanner",
    "JavaScriptScanner",
    "JavaScanner",
    "SUPPORTED_EXTENSIONS",
]
