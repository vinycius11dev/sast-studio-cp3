# Imagem base Python slim para ambiente seguro e leve
FROM python:3.11-slim

# Metadados da imagem
LABEL maintainer="FIAP DevSecOps Team"
LABEL description="Plataforma SAST & DevSecOps - Motor de Análise Estática de Segurança"
LABEL version="3.0.0"

# Evita criação de arquivos .pyc e força flush imediato nos logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# Instalação de dependências do sistema necessárias para compilação ou utilitários
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Instalação de dependências Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Optional tools use a separate interpreter, without changing API dependencies.
ARG WITH_SCANNERS=0
COPY requirements-scanners.txt .
RUN if [ "$WITH_SCANNERS" = "1" ]; then python -m venv /opt/scanners && /opt/scanners/bin/pip install --no-cache-dir -r requirements-scanners.txt; fi

# Criação de usuário não-root para execução segura (Princípio do Menor Privilégio)
RUN useradd -m -u 1001 sastuser

# Cópia do código-fonte da aplicação
COPY engine/ /app/engine/
COPY config/ /app/config/
COPY api/ /app/api/
COPY static/ /app/static/
COPY samples/ /app/samples/
COPY demonstracao/ /app/demonstracao/
COPY docs/screenshots/readme/ /app/docs/screenshots/readme/
COPY docs/benchmark-results.json /app/docs/benchmark-results.json
COPY docs/quality/owasp-native-results.json /app/docs/quality/owasp-native-results.json
COPY cli.py /app/cli.py
COPY .github/workflows/ /app/.github/workflows/

# Ajuste de permissões
RUN mkdir -p /app/data && chown -R sastuser:sastuser /app

# Troca para usuário não-root
USER sastuser

# Exposição da porta da API
EXPOSE 8000

# Healthcheck do container
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Comando de inicialização do servidor Uvicorn
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
