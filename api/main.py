"""API e workspace local de análise estática de segurança."""
import json
import os
import time
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Literal, Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from api.store import HistoryBusyError, ScanStore
from api.jobs import JobStore, ScanJob
from engine.ai_remediation import AIRemediationEngine, AIRemediationResponse
from engine.engine import IGNORE_DIRS, SASTEngine
from engine.languages import SUPPORTED_EXTENSIONS
from engine.models import Finding, RuleMetadata, ScannedFile, ScanResult, SemanticReview
from engine.semantic_review import AISemanticReviewEngine
from engine.reporter import Reporter

ROOT_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT_DIR / "static"
PRESENTATION_ASSETS_DIR = ROOT_DIR / "docs" / "screenshots" / "readme"
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024
MAX_PROJECT_FILES = 200
MAX_PROJECT_SIZE_BYTES = 25 * 1024 * 1024
SUPPORTED_UPLOAD_EXTENSIONS = set(SUPPORTED_EXTENSIONS)
GateThreshold = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]

@asynccontextmanager
async def lifespan(app):
    stop, worker = threading.Event(), None
    job_store.initialize()
    if os.getenv("SAST_EMBEDDED_WORKER", "1") == "1":
        from api.worker import run_worker
        worker = threading.Thread(target=run_worker, args=(job_store, _execute_scan, stop), daemon=True)
        worker.start()
    try:
        yield
    finally:
        stop.set()
        if worker:
            await run_in_threadpool(worker.join, 5)


app = FastAPI(title="SAST Studio API", description="Workspace local de segurança de código e remediação assistida.", version="3.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.mount("/presentation-assets", StaticFiles(directory=PRESENTATION_ASSETS_DIR), name="presentation-assets")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(","),
    allow_credentials=True, allow_methods=["GET", "POST", "DELETE"], allow_headers=["*"],
)
sast_engine = SASTEngine()
ai_engine = AIRemediationEngine()
semantic_engine = AISemanticReviewEngine(ai_engine)
scan_store = ScanStore(Path(os.getenv("SAST_DATA_DIR", str(ROOT_DIR / "data"))) / "scans.sqlite3")
job_store = JobStore(Path(os.getenv("SAST_DATA_DIR", str(ROOT_DIR / "data"))) / "jobs.sqlite3")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'"
    response.headers["Cache-Control"] = "no-cache"
    return response


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/dashboard")


@app.get("/dashboard", include_in_schema=False)
def dashboard_page():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/apresentacao", include_in_schema=False)
@app.get("/presentation", include_in_schema=False)
def presentation_page():
    return FileResponse(STATIC_DIR / "presentation.html")


@app.get("/health", tags=["Status"])
def health_check():
    return {"status": "healthy", "service": "sast-engine-api", "version": "3.0.0", "active_rules": len(sast_engine.list_rules())}


@app.get("/api/v1/capabilities", tags=["Status"])
def capabilities():
    return {
        "limits": {"file_bytes": MAX_FILE_SIZE_BYTES, "project_bytes": MAX_PROJECT_SIZE_BYTES, "project_files": MAX_PROJECT_FILES},
        "extensions": sorted(SUPPORTED_UPLOAD_EXTENSIONS), "ignored_directories": sorted(IGNORE_DIRS),
        "languages": [
            {"id": "python", "name": "Python", "technique": "AST + análise básica de fluxo de dados", "extensions": [".py"]},
            {"id": "javascript", "name": "JavaScript / TypeScript", "technique": "AST Tree-sitter e regras estruturais", "extensions": [".js", ".jsx", ".ts", ".tsx"]},
            {"id": "java", "name": "Java", "technique": "AST Tree-sitter e regras estruturais", "extensions": [".java"]},
        ],
    }


@app.get("/api/v1/ai/status", tags=["Inteligência Artificial"])
def ai_status():
    return ai_engine.get_status()


@app.get("/api/v1/rules", response_model=List[RuleMetadata], tags=["Regras"])
def list_rules():
    return sast_engine.list_rules()


def _safe_project_upload_path(filename: str) -> str:
    normalized = (filename or "").replace("\\", "/")
    parts = normalized.split("/")
    if (not normalized or len(normalized) > 512 or normalized.startswith("/")
            or ":" in normalized or any(ord(char) < 32 for char in normalized)
            or any(part in {"", ".", ".."} for part in parts)):
        raise HTTPException(400, "Caminho relativo de arquivo inválido.")
    return "/".join(parts)


def _decode_source(data: bytes, filename: str) -> str:
    if not data.strip():
        raise HTTPException(400, f"O arquivo {filename} está vazio.")
    if b"\x00" in data:
        raise HTTPException(400, f"O arquivo {filename} contém dados binários.")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _execute_scan(sources: Dict[str, str], project_name: str, threshold: str, ignored: int = 0) -> ScanResult:
    started = time.perf_counter()
    findings, errors, file_reports = [], [], []
    for path, source in sorted(sources.items()):
        result = sast_engine.scan_code(source, identifier=path)
        findings.extend(result.findings)
        errors.extend(result.errors)
        file_reports.append(ScannedFile(
            path=path, language=SUPPORTED_EXTENSIONS[Path(path).suffix.lower()],
            size_bytes=len(source.encode("utf-8")), findings_count=result.total_findings,
            status="error" if result.has_errors else "completed",
        ))
    result = ScanResult(
        target_path=project_name, scanned_files_count=sum(item.status == "completed" for item in file_reports),
        total_findings=len(findings), findings=findings, files=file_reports,
        summary_by_severity=sast_engine._build_summary(findings),
        scan_duration_ms=round((time.perf_counter() - started) * 1000, 2),
        has_errors=bool(errors), errors=errors, ignored_files_count=ignored,
    )
    return scan_store.save(result, sources, project_name, threshold)


class CodeScanRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=500_000)
    filename: str = Field(default="snippet.py", max_length=200)
    project_name: Optional[str] = Field(default=None, max_length=120)
    gate_threshold: GateThreshold = "HIGH"


@app.post("/api/v1/scan/code", response_model=ScanResult, responses={202: {"model": ScanJob}}, tags=["Análise"])
def scan_code_snippet(payload: CodeScanRequest, queued: bool = Query(False)):
    path = _safe_project_upload_path(payload.filename)
    if Path(path).suffix.lower() not in SUPPORTED_UPLOAD_EXTENSIONS:
        raise HTTPException(400, "Extensão não suportada. Use .py, .js, .jsx, .ts, .tsx ou .java.")
    if not payload.code.strip():
        raise HTTPException(400, "Informe código-fonte antes de analisar.")
    project = (payload.project_name or path).strip()
    if queued:
        return JSONResponse(status_code=202, content=job_store.submit({path: payload.code}, project, payload.gate_threshold).model_dump(mode="json"))
    return _execute_scan({path: payload.code}, project, payload.gate_threshold)


@app.post("/api/v1/scan/file", response_model=ScanResult, responses={202: {"model": ScanJob}}, tags=["Análise"])
async def scan_uploaded_file(file: UploadFile = File(...), project_name: str = Form("", max_length=120), gate_threshold: GateThreshold = Form("HIGH"), queued: bool = Query(False)):
    path = _safe_project_upload_path(file.filename or "upload.py").split("/")[-1]
    if Path(path).suffix.lower() not in SUPPORTED_UPLOAD_EXTENSIONS:
        raise HTTPException(400, "Extensão não suportada. Use .py, .js, .jsx, .ts, .tsx ou .java.")
    data = await file.read(MAX_FILE_SIZE_BYTES + 1)
    await file.close()
    if len(data) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(413, "Arquivo excede o limite de 5 MB.")
    source = _decode_source(data, path)
    if queued:
        return JSONResponse(status_code=202, content=job_store.submit({path: source}, project_name.strip() or path, gate_threshold).model_dump(mode="json"))
    return await run_in_threadpool(_execute_scan, {path: source}, project_name.strip() or path, gate_threshold)


@app.post("/api/v1/scan/project", response_model=ScanResult, responses={202: {"model": ScanJob}}, tags=["Análise"])
async def scan_uploaded_project(files: List[UploadFile] = File(...), project_name: str = Form("", max_length=120), gate_threshold: GateThreshold = Form("HIGH"), queued: bool = Query(False)):
    sources, total_bytes, ignored = {}, 0, 0
    for uploaded in files:
        path = _safe_project_upload_path(uploaded.filename or "")
        parts = path.lower().split("/")
        if Path(path).suffix.lower() not in SUPPORTED_UPLOAD_EXTENSIONS or any(part in IGNORE_DIRS for part in parts[:-1]):
            ignored += 1
            await uploaded.close()
            continue
        if path in sources:
            raise HTTPException(400, f"Caminho duplicado na pasta: {path}.")
        if len(sources) >= MAX_PROJECT_FILES:
            raise HTTPException(413, f"A pasta excede o limite de {MAX_PROJECT_FILES} arquivos de código.")
        data = await uploaded.read(MAX_FILE_SIZE_BYTES + 1)
        await uploaded.close()
        if len(data) > MAX_FILE_SIZE_BYTES:
            raise HTTPException(413, f"{path} excede o limite de 5 MB por arquivo.")
        total_bytes += len(data)
        if total_bytes > MAX_PROJECT_SIZE_BYTES:
            raise HTTPException(413, "A pasta excede o limite total de 25 MB.")
        if not data.strip():
            ignored += 1
            continue
        sources[path] = _decode_source(data, path)
    if not sources:
        raise HTTPException(400, "A pasta não contém arquivos de código suportados com conteúdo.")
    default_name = next(iter(sources)).split("/")[0]
    if queued:
        return JSONResponse(status_code=202, content=job_store.submit(sources, project_name.strip() or default_name, gate_threshold, ignored).model_dump(mode="json"))
    return await run_in_threadpool(_execute_scan, sources, project_name.strip() or default_name, gate_threshold, ignored)


@app.get("/api/v1/samples", tags=["Demonstração"])
def sample_sources(variant: Literal["all", "vulneravel", "corrigido"] = "all"):
    folders = {"vulneravel": "01-vulneravel", "corrigido": "02-corrigido"}
    directory = ROOT_DIR / "demonstracao" / folders[variant] if variant in folders else ROOT_DIR / "samples"
    if not directory.is_dir():
        raise HTTPException(404, "Pasta de exemplo indisponível nesta instalação.")
    return {
        "project_name": {"vulneravel": "Demonstração · Antes da correção", "corrigido": "Demonstração · Depois da correção"}.get(variant, "Projeto de demonstração"),
        "files": [{"path": f"{directory.name}/{path.relative_to(directory).as_posix()}",
                   "content": path.read_text(encoding="utf-8"),
                   "language": SUPPORTED_EXTENSIONS[path.suffix.lower()]}
                  for path in sorted(directory.rglob("*"))
                  if path.is_file() and path.suffix.lower() in SUPPORTED_UPLOAD_EXTENSIONS],
    }


@app.get("/api/v1/scan/samples", response_model=ScanResult, tags=["Demonstração"])
def scan_samples_endpoint():
    sources = {item["path"]: item["content"] for item in sample_sources()["files"]}
    return _execute_scan(sources, "Projeto de demonstração", "HIGH")


@app.get("/api/v1/scans", tags=["Histórico"])
def scans(limit: int = Query(100, ge=1, le=500)):
    return {"items": scan_store.list(limit)}


class ClearHistoryRequest(BaseModel):
    confirmation: Literal["CLEAR_HISTORY"]


@app.delete("/api/v1/scans", tags=["Histórico"])
def clear_history(payload: ClearHistoryRequest):
    try:
        return scan_store.clear(job_store)
    except HistoryBusyError as error:
        raise HTTPException(409, str(error)) from error


def _get_scan(scan_id: str) -> ScanResult:
    result = scan_store.get(scan_id)
    if result is None:
        raise HTTPException(404, "Análise não encontrada no histórico local.")
    return result


@app.get("/api/v1/scans/{scan_id}", response_model=ScanResult, tags=["Histórico"])
def get_scan(scan_id: str):
    return _get_scan(scan_id)


@app.get("/api/v1/scans/{scan_id}/source", tags=["Histórico"])
def get_scan_source(scan_id: str, path: str = Query(..., max_length=512)):
    _get_scan(scan_id)
    source = scan_store.source(scan_id, path)
    if source is None:
        raise HTTPException(404, "Arquivo não encontrado nesta análise.")
    return {"path": path, "content": source, "line_count": len(source.splitlines())}


def _report_response(result: ScanResult, format: str):
    if format == "sarif":
        content, media_type, extension = Reporter.to_sarif(result), "application/sarif+json", "sarif"
    elif format == "json":
        content, media_type, extension = Reporter.to_json(result), "application/json", "json"
    else:
        content, media_type, extension = Reporter.to_markdown(result), "text/markdown; charset=utf-8", "md"
    return Response(content=content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="sast-{result.scan_id}.{extension}"'})


@app.get("/api/v1/scans/{scan_id}/report", tags=["Relatórios"])
def export_scan_report(scan_id: str, format: Literal["sarif", "json", "markdown"] = "sarif"):
    return _report_response(_get_scan(scan_id), format)


@app.get("/api/v1/report/sarif", tags=["Relatórios"])
def export_sarif_endpoint(scan_id: Optional[str] = None):
    if not scan_id:
        latest = scan_store.list(1)
        if not latest:
            raise HTTPException(404, "Execute uma análise antes de exportar o relatório.")
        scan_id = latest[0]["scan_id"]
    return _report_response(_get_scan(scan_id), "sarif")


class RemediationRequest(Finding):
    original_code: Optional[str] = Field(default=None, max_length=20_000)
    scan_id: Optional[str] = Field(default=None, max_length=32)


@app.post("/api/v1/remediate", response_model=AIRemediationResponse, tags=["Inteligência Artificial"])
def remediate_finding_endpoint(finding: RemediationRequest):
    source = finding.original_code
    if finding.scan_id:
        saved = _get_scan(finding.scan_id)
        if not any(item.file_path == finding.file_path and item.line_number == finding.line_number
                   and item.rule_id == finding.rule_id and item.code_snippet == finding.code_snippet for item in saved.findings):
            raise HTTPException(400, "O achado não pertence à análise informada.")
        source = scan_store.source(finding.scan_id, finding.file_path)
    return ai_engine.remediate_finding(finding, original_code=source)


@app.get("/api/v1/integrations/workflow", tags=["Integrações"])
def workflow_template():
    path = ROOT_DIR / ".github" / "workflows" / "sast_security_gate.yml"
    if not path.exists():
        raise HTTPException(404, "Workflow indisponível nesta instalação. Consulte o README.")
    return FileResponse(path, filename="sast_security_gate.yml", media_type="text/yaml")


class SemanticReviewRequest(Finding):
    scan_id: str = Field(min_length=32, max_length=32)


@app.get("/api/v1/jobs/status", tags=["Fila"])
def queue_status():
    return job_store.status()


@app.get("/api/v1/jobs/{job_id}", response_model=ScanJob, tags=["Fila"])
def job_status(job_id: str):
    job = job_store.get(job_id)
    if job is None:
        raise HTTPException(404, "Análise em fila não encontrada.")
    return job


@app.post("/api/v1/triage", response_model=SemanticReview, tags=["Inteligência Artificial"])
def review_finding_endpoint(payload: SemanticReviewRequest):
    saved = _get_scan(payload.scan_id)
    original = next((finding for finding in saved.findings if finding.rule_id == payload.rule_id
                     and finding.file_path == payload.file_path and finding.line_number == payload.line_number
                     and finding.column_number == payload.column_number and finding.code_snippet == payload.code_snippet), None)
    if original is None:
        raise HTTPException(400, "O achado não pertence à análise informada.")
    source = scan_store.source(payload.scan_id, original.file_path)
    if source is None:
        raise HTTPException(404, "Código-fonte indisponível para revisão.")
    review = semantic_engine.review_finding(original, source, payload.scan_id)
    try:
        return scan_store.save_review(review)
    except ValueError as error:
        raise HTTPException(409, str(error)) from error
