"""Versioned OWASP Top 10 taxonomy mappings for supported CWE findings."""

from typing import Optional

from pydantic import BaseModel


class OwaspCategory(BaseModel):
    id: str
    name: str
    version: str
    url: str


_CATEGORIES = {
    "A01:2025": OwaspCategory(
        id="A01:2025",
        name="Controle de Acesso Quebrado",
        version="2025",
        url="https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/",
    ),
    "A05:2025": OwaspCategory(
        id="A05:2025",
        name="Injeção",
        version="2025",
        url="https://top10.owasp.org/2025/A05_2025-Injection/",
    ),
    "A07:2025": OwaspCategory(
        id="A07:2025",
        name="Falhas de Autenticação",
        version="2025",
        url="https://top10.owasp.org/2025/A07_2025-Authentication_Failures/",
    ),
    "A08:2025": OwaspCategory(
        id="A08:2025",
        name="Falhas de Integridade de Software ou de Dados",
        version="2025",
        url="https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/",
    ),
}

# These categories follow OWASP Top 10:2025's mapped CWE lists. Findings without
# a listed CWE remain unclassified instead of receiving a guessed category.
CWE_TO_OWASP = {
    "CWE-22": "A01:2025",   # Path traversal
    "CWE-78": "A05:2025",   # OS command injection
    "CWE-79": "A05:2025",   # Cross-site scripting
    "CWE-89": "A05:2025",   # SQL injection
    "CWE-95": "A05:2025",   # Eval injection
    "CWE-502": "A08:2025",  # Insecure deserialization
    "CWE-798": "A07:2025",  # Hard-coded credentials
    "CWE-918": "A01:2025",  # SSRF
}


def owasp_category_for_cwe(cwe: str) -> Optional[OwaspCategory]:
    """Return the OWASP Top 10:2025 category explicitly associated with a CWE."""
    category_id = CWE_TO_OWASP.get(cwe)
    category = _CATEGORIES.get(category_id or "")
    return category.model_copy(deep=True) if category else None
