"""Lightweight RAG-style security intel retrieval service for agent planning."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Any


DEFAULT_RAG_CORPUS_ENV = "AUTOSECAUDIT_RAG_CORPUS_FILE"
DEFAULT_RAG_CORPUS_PATH = Path("config/rag/intel_corpus.json")
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{1,48}", flags=re.IGNORECASE)


_BUILTIN_CORPUS: tuple[dict[str, Any], ...] = (
    {
        "id": "wp-xmlrpc-bruteforce-surface",
        "title": "WordPress XML-RPC Attack Surface",
        "summary": "WordPress often exposes /xmlrpc.php; verify method abuse and hardening.",
        "content": "Check xmlrpc pingback and multicall behavior. Prioritize non-destructive probes first.",
        "tags": ["wordpress", "xmlrpc", "cms", "auth"],
        "recommended_tools": ["nuclei_exploit_check", "passive_config_audit", "cve_lookup"],
        "severity_hint": "medium",
        "references": ["https://wordpress.org/documentation/article/xml-rpc-support/"],
    },
    {
        "id": "nginx-alias-traversal-patterns",
        "title": "Nginx Alias Traversal Misconfiguration",
        "summary": "Look for location/alias path traversal style weaknesses and leaked static roots.",
        "content": "Fingerprint static file roots, test normalized and encoded traversal payloads safely.",
        "tags": ["nginx", "traversal", "misconfig", "path"],
        "recommended_tools": ["dirsearch_scan", "passive_config_audit", "nuclei_exploit_check"],
        "severity_hint": "high",
        "references": ["https://nvd.nist.gov/"],
    },
    {
        "id": "spring-actuator-and-env-exposure",
        "title": "Spring Boot Actuator and Env Exposure",
        "summary": "Spring deployments may expose actuator endpoints and configuration metadata.",
        "content": "Probe /actuator and common management endpoints. Validate safe endpoint exposure policy.",
        "tags": ["spring", "actuator", "java", "config"],
        "recommended_tools": ["passive_config_audit", "api_schema_discovery", "cve_lookup"],
        "severity_hint": "medium",
        "references": ["https://spring.io/projects/spring-boot"],
    },
    {
        "id": "jenkins-unauth-endpoint-hardening",
        "title": "Jenkins Endpoint Exposure and Legacy CVEs",
        "summary": "Jenkins often exposes metadata endpoints; verify auth and known CVE coverage.",
        "content": "Audit login flow, crumbs API, and plugin version signals before exploit validation.",
        "tags": ["jenkins", "ci", "auth", "plugins"],
        "recommended_tools": ["login_form_detector", "cve_lookup", "nuclei_exploit_check"],
        "severity_hint": "high",
        "references": ["https://www.jenkins.io/security/"],
    },
    {
        "id": "react-source-map-debug-leakage",
        "title": "React Source Map and Debug Artifact Exposure",
        "summary": "React/SPA builds may leak source maps and internal routes.",
        "content": "Verify source map leakage, stack traces, and client-side route enumeration.",
        "tags": ["react", "spa", "source-map", "frontend"],
        "recommended_tools": ["source_map_detector", "error_page_analyzer", "api_schema_discovery"],
        "severity_hint": "low",
        "references": ["https://owasp.org/"],
    },
    {
        "id": "graphql-introspection-and-idor",
        "title": "GraphQL Introspection and Authorization Gaps",
        "summary": "GraphQL endpoints may permit schema introspection and weak object authorization.",
        "content": "Discover GraphQL schema and inspect resolver auth behavior with low-risk probes.",
        "tags": ["graphql", "idor", "api", "schema"],
        "recommended_tools": ["api_schema_discovery", "param_fuzzer", "cve_lookup"],
        "severity_hint": "medium",
        "references": ["https://cheatsheetseries.owasp.org/"],
    },
    {
        "id": "openssh-legacy-version-review",
        "title": "OpenSSH Legacy Version Review",
        "summary": "Legacy OpenSSH banners should trigger version-aware CVE lookup and bounded validation.",
        "content": "Capture the exact SSH banner, map the version, then prefer CVE lookup and safe sandbox probes for confirmed legacy branches.",
        "tags": ["ssh", "openssh", "dropbear", "banner", "legacy"],
        "recommended_tools": ["cve_lookup", "poc_sandbox_exec"],
        "severity_hint": "medium",
        "references": ["https://www.openssh.com/security.html"],
    },
    {
        "id": "redis-public-exposure-patterns",
        "title": "Redis Public Exposure and Weak Boundary Patterns",
        "summary": "Redis instances reachable without authentication warrant immediate bounded validation and version review.",
        "content": "Correlate unauthenticated PING/INFO behavior with version metadata, then prioritize CVE lookup and safe protocol-level sandbox validation.",
        "tags": ["redis", "cache", "unauthenticated", "service-exposure"],
        "recommended_tools": ["cve_lookup", "poc_sandbox_exec"],
        "severity_hint": "high",
        "references": ["https://redis.io/docs/latest/operate/oss_and_stack/management/security/"],
    },
    {
        "id": "memcached-public-stats-exposure",
        "title": "Memcached Public Exposure and Stats Leakage",
        "summary": "Public memcached responses often indicate broad unauthenticated exposure and version-bearing metadata.",
        "content": "Use bounded version and stats probes, then drive CVE lookup and safe sandbox validation from the discovered version.",
        "tags": ["memcached", "cache", "stats", "unauthenticated"],
        "recommended_tools": ["cve_lookup", "poc_sandbox_exec"],
        "severity_hint": "high",
        "references": ["https://memcached.org/"],
    },
    {
        "id": "legacy-tls-handshake-hardening",
        "title": "Legacy TLS Handshake and HTTPS Validation",
        "summary": "Legacy TLS protocol support should escalate into targeted HTTPS validation and hardening review.",
        "content": "When TLSv1/TLSv1.1 or weak transport traits are observed, feed the origin back into template-based HTTPS validation and passive hardening checks.",
        "tags": ["tls", "https", "tlsv1", "tlsv1.1", "transport"],
        "recommended_tools": ["nuclei_exploit_check", "passive_config_audit"],
        "severity_hint": "medium",
        "references": ["https://owasp.org/www-project-transport-layer-protection-cheat-sheet/"],
    },
)


@dataclass(frozen=True)
class RagIntelHit:
    """One ranked RAG retrieval hit."""

    doc_id: str
    title: str
    summary: str
    snippet: str
    source: str
    tags: list[str]
    recommended_tools: list[str]
    severity_hint: str
    references: list[str]
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "title": self.title,
            "summary": self.summary,
            "snippet": self.snippet,
            "source": self.source,
            "tags": list(self.tags),
            "recommended_tools": list(self.recommended_tools),
            "severity_hint": self.severity_hint,
            "references": list(self.references),
            "score": round(float(self.score), 4),
        }


@dataclass(frozen=True)
class _RagDocument:
    doc_id: str
    title: str
    summary: str
    content: str
    source: str
    tags: list[str]
    recommended_tools: list[str]
    severity_hint: str
    references: list[str]
    tokens: set[str]


class RagIntelService:
    """Retrieve security testing intelligence from local corpus + builtin knowledge."""

    _DOC_CACHE: dict[str, tuple[float, list[_RagDocument]]] = {}

    def __init__(self, *, corpus_path: str | Path | None = None) -> None:
        raw_path = str(
            corpus_path
            or os.getenv(DEFAULT_RAG_CORPUS_ENV, "").strip()
            or DEFAULT_RAG_CORPUS_PATH
        ).strip()
        self._corpus_path = Path(raw_path).expanduser()
        self._documents = self._load_documents(self._corpus_path)

    @property
    def corpus_path(self) -> Path:
        return self._corpus_path

    def search(
        self,
        *,
        query: str = "",
        component: str | None = None,
        version: str | None = None,
        tech_stack: list[str] | None = None,
        max_results: int = 8,
        min_score: float = 1.0,
    ) -> list[dict[str, Any]]:
        """
        Retrieve ranked intel snippets.

        This is intentionally lightweight lexical retrieval for MVP reliability.
        """
        max_results = max(1, min(int(max_results or 8), 20))
        query_tokens = self._build_query_tokens(
            query=query,
            component=component,
            version=version,
            tech_stack=tech_stack or [],
        )
        if not query_tokens:
            return []

        scored: list[RagIntelHit] = []
        for document in self._documents:
            score = self._score_document(document, query_tokens=query_tokens)
            if score < float(min_score):
                continue
            scored.append(
                RagIntelHit(
                    doc_id=document.doc_id,
                    title=document.title,
                    summary=document.summary,
                    snippet=self._build_snippet(document, query_tokens=query_tokens),
                    source=document.source,
                    tags=list(document.tags),
                    recommended_tools=list(document.recommended_tools),
                    severity_hint=document.severity_hint,
                    references=list(document.references),
                    score=score,
                )
            )
        ranked = sorted(
            scored,
            key=lambda item: (-item.score, item.doc_id),
        )
        return [item.to_dict() for item in ranked[:max_results]]

    def _load_documents(self, corpus_path: Path) -> list[_RagDocument]:
        cache_key = str(corpus_path.resolve()).lower()
        mtime = -1.0
        if corpus_path.exists() and corpus_path.is_file():
            try:
                mtime = float(corpus_path.stat().st_mtime)
            except OSError:
                mtime = -1.0

        cached = self._DOC_CACHE.get(cache_key)
        if cached is not None and cached[0] == mtime:
            return list(cached[1])

        docs: list[_RagDocument] = []
        docs.extend(self._coerce_documents(_BUILTIN_CORPUS, source_hint="builtin"))
        docs.extend(self._coerce_documents(self._load_external_payload(corpus_path), source_hint="file"))
        deduped = self._dedupe_documents(docs)
        self._DOC_CACHE[cache_key] = (mtime, deduped)
        return list(deduped)

    @staticmethod
    def _load_external_payload(corpus_path: Path) -> list[dict[str, Any]]:
        if not corpus_path.exists() or not corpus_path.is_file():
            return []
        try:
            payload = json.loads(corpus_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return []
        if isinstance(payload, dict):
            raw_docs = payload.get("documents", [])
            return [item for item in raw_docs if isinstance(item, dict)] if isinstance(raw_docs, list) else []
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []

    def _coerce_documents(self, raw_docs: list[dict[str, Any]], *, source_hint: str) -> list[_RagDocument]:
        output: list[_RagDocument] = []
        for raw in raw_docs:
            doc_id = str(raw.get("id", "")).strip().lower()
            title = str(raw.get("title", "")).strip()
            if not doc_id or not title:
                continue
            summary = str(raw.get("summary", "")).strip()
            content = str(raw.get("content", "")).strip()
            source = str(raw.get("source", "")).strip() or source_hint
            tags = [
                str(item).strip().lower()
                for item in (raw.get("tags", []) if isinstance(raw.get("tags", []), list) else [])
                if str(item).strip()
            ]
            recommended_tools = [
                str(item).strip()
                for item in (raw.get("recommended_tools", []) if isinstance(raw.get("recommended_tools", []), list) else [])
                if str(item).strip()
            ]
            severity_hint = str(raw.get("severity_hint", "info")).strip().lower() or "info"
            references = [
                str(item).strip()
                for item in (raw.get("references", []) if isinstance(raw.get("references", []), list) else [])
                if str(item).strip()
            ]
            token_source = "\n".join([title, summary, content, " ".join(tags)])
            tokens = self._tokenize(token_source)
            if not tokens:
                continue
            output.append(
                _RagDocument(
                    doc_id=doc_id,
                    title=title,
                    summary=summary,
                    content=content,
                    source=source,
                    tags=tags,
                    recommended_tools=recommended_tools,
                    severity_hint=severity_hint,
                    references=references,
                    tokens=tokens,
                )
            )
        return output

    @staticmethod
    def _dedupe_documents(documents: list[_RagDocument]) -> list[_RagDocument]:
        deduped: dict[str, _RagDocument] = {}
        for item in documents:
            deduped[item.doc_id] = item
        return [deduped[key] for key in sorted(deduped)]

    def _score_document(self, document: _RagDocument, *, query_tokens: set[str]) -> float:
        score = 0.0
        tag_set = {str(item).strip().lower() for item in document.tags if str(item).strip()}
        title_tokens = self._tokenize(document.title)
        summary_tokens = self._tokenize(document.summary)
        for token in query_tokens:
            if token in title_tokens:
                score += 3.0
            elif token in summary_tokens:
                score += 2.0
            elif token in tag_set:
                score += 2.0
            elif token in document.tokens:
                score += 1.0
        if tag_set & query_tokens:
            score += 1.0
        return score

    def _build_snippet(self, document: _RagDocument, *, query_tokens: set[str]) -> str:
        source = document.content or document.summary or document.title
        compact = re.sub(r"\s+", " ", source).strip()
        if not compact:
            return ""
        lower_compact = compact.lower()
        hit_index = -1
        for token in query_tokens:
            idx = lower_compact.find(token)
            if idx >= 0 and (hit_index < 0 or idx < hit_index):
                hit_index = idx
        if hit_index < 0 or len(compact) <= 240:
            return compact[:240]
        start = max(0, hit_index - 80)
        end = min(len(compact), start + 240)
        return compact[start:end]

    def _build_query_tokens(
        self,
        *,
        query: str,
        component: str | None,
        version: str | None,
        tech_stack: list[str],
    ) -> set[str]:
        pieces = [str(query).strip(), str(component or "").strip(), str(version or "").strip()]
        pieces.extend(str(item).strip() for item in tech_stack if str(item).strip())
        return self._tokenize(" ".join(pieces))

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        tokens: set[str] = set()
        for match in _TOKEN_RE.finditer(str(text).lower()):
            token = match.group(0).strip("._:-")
            if len(token) < 2:
                continue
            tokens.add(token)
        return tokens
