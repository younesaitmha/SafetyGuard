from __future__ import annotations

import hashlib
import hmac
import re
from typing import List

import httpx

from .config import settings
from .dlp_engine import DETECTORS, build_scan_result, scan_text_with_detectors
from .models import CanonicalRequestEnvelope, DLPScanResult, RetrievalChunk, RetrievalResult


class RetrievalGateway:
    async def retrieve(self, envelope: CanonicalRequestEnvelope) -> RetrievalResult:
        if not envelope.policy_decision or not envelope.policy_decision.allow_retrieval:
            return RetrievalResult(
                query=self._build_query(envelope),
                chunks=[],
                filtered_out_count=0,
                allowed_count=0,
                dlp_scan=DLPScanResult(score=0, labels=[], matches=[], summary={"match_count": 0}),
            )

        query = self._build_query(envelope)
        raw_chunks = await self._fetch_chunks(query, envelope)
        filtered_chunks, filtered_out, integrity_filtered = self._filter_chunks(raw_chunks, envelope)
        safe_chunks, injection_filtered = self._filter_chunks_for_injection(filtered_chunks)

        return RetrievalResult(
            query=query,
            chunks=safe_chunks,
            filtered_out_count=filtered_out,
            injection_filtered_count=injection_filtered,
            integrity_filtered_count=integrity_filtered,
            allowed_count=len(safe_chunks),
            dlp_scan=self._scan_chunks(safe_chunks),
        )

    def _build_query(self, envelope: CanonicalRequestEnvelope) -> str:
        user_messages = [m.content for m in envelope.messages if m.role == "user"]
        return "\n".join(user_messages[-3:]).strip()

    async def _fetch_chunks(self, query: str, envelope: CanonicalRequestEnvelope) -> List[RetrievalChunk]:
        url = f"{settings.retrieval_backend_url}/internal/retrieve"
        payload = {
            "query": query,
            "top_k": settings.retrieval_top_k,
            "tenant_id": envelope.security_context.tenant_id,
            "trace_id": envelope.trace_id,
        }

        try:
            async with httpx.AsyncClient(timeout=settings.retrieval_timeout_seconds) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except Exception:
            data = {
                "chunks": [
                    {
                        "chunk_id": "c1",
                        "document_id": "doc1",
                        "text": "General internal support guidance for password reset procedures.",
                        "score": 0.91,
                        "source_uri": "kb://support/doc1",
                        "tenant_id": envelope.security_context.tenant_id,
                        "sensitivity": "internal",
                        "trust_level": "semi_trusted",
                        "metadata": {"source": "knowledge_base"},
                    },
                    {
                        "chunk_id": "c2",
                        "document_id": "doc2",
                        "text": "Confidential admin escalation process and emergency access workflow.",
                        "score": 0.72,
                        "source_uri": "kb://security/doc2",
                        "tenant_id": envelope.security_context.tenant_id,
                        "sensitivity": "confidential",
                        "trust_level": "semi_trusted",
                        "metadata": {"source": "knowledge_base"},
                    },
                ]
            }

        return [RetrievalChunk.model_validate(item) for item in data.get("chunks", [])]

    def _filter_chunks(self, chunks: List[RetrievalChunk], envelope: CanonicalRequestEnvelope) -> tuple[List[RetrievalChunk], int, int]:
        allowed: List[RetrievalChunk] = []
        filtered_out = 0
        integrity_filtered = 0
        tenant_id = envelope.security_context.tenant_id
        max_sensitivity = envelope.policy_decision.max_context_sensitivity if envelope.policy_decision else "internal"
        sensitivity_rank = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}

        for chunk in chunks:
            if tenant_id and chunk.tenant_id and chunk.tenant_id != tenant_id:
                filtered_out += 1
                continue

            if sensitivity_rank[chunk.sensitivity] > sensitivity_rank[max_sensitivity]:
                filtered_out += 1
                continue

            if not self._is_chunk_integrity_valid(chunk):
                integrity_filtered += 1
                continue

            allowed.append(chunk)

        return allowed, filtered_out, integrity_filtered

    def _is_chunk_integrity_valid(self, chunk: RetrievalChunk) -> bool:
        if chunk.content_hash:
            digest = hashlib.sha256(chunk.text.encode("utf-8")).hexdigest()
            if digest != chunk.content_hash:
                return False

        if chunk.source_signature and settings.retrieval_integrity_key:
            expected = hmac.new(
                settings.retrieval_integrity_key.encode("utf-8"),
                chunk.text.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, chunk.source_signature):
                return False

        return True

    def _filter_chunks_for_injection(self, chunks: List[RetrievalChunk]) -> tuple[List[RetrievalChunk], int]:
        """Remove retrieved chunks that contain prompt injection patterns (indirect prompt injection protection)."""
        _INJECTION_PATTERNS = [
            r"ignore previous instructions",
            r"disregard (all |your )?(prior |previous )?(rules|instructions)",
            r"you are now\b",
            r"pretend you are",
            r"\bjailbreak\b",
            r"act as if you (are|have|were)",
            r"bypass.{0,20}(filter|guard|policy|safety)",
        ]
        safe: List[RetrievalChunk] = []
        filtered = 0
        for chunk in chunks:
            text = chunk.text.lower()
            if any(re.search(p, text) for p in _INJECTION_PATTERNS):
                filtered += 1
            else:
                safe.append(chunk)
        return safe, filtered

    def _scan_chunks(self, chunks: List[RetrievalChunk]) -> DLPScanResult:
        matches = []
        labels: set[str] = set()
        score = 0
        for idx, chunk in enumerate(chunks):
            chunk_matches, chunk_labels, chunk_score = scan_text_with_detectors(
                chunk.text,
                DETECTORS,
                message_index=idx,
            )
            matches.extend(chunk_matches)
            labels.update(chunk_labels)
            score += chunk_score

        return build_scan_result(matches, labels, score)
