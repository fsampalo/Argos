"""Tests for core data models and risk scoring."""

from argos.core.models import (
    Fingerprint,
    RiskFinding,
    RiskReport,
    Severity,
    Threat,
)
from argos.core.taxonomies import OWASP_MCP_TOP_10, get_owasp_risk


def test_severity_scores_are_ordered() -> None:
    scores = [s.score for s in (
        Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL
    )]
    assert scores == sorted(scores)
    assert scores[0] == 0.0 and scores[-1] == 1.0


def test_empty_report_scores_zero() -> None:
    report = RiskReport(server_name="empty")
    assert report.compute_score() == 0.0


def test_report_score_saturates_and_ranks() -> None:
    low = RiskReport(server_name="low", findings=[
        RiskFinding(owasp_id="MCP08", title="x", severity=Severity.LOW, description=""),
    ])
    critical = RiskReport(server_name="crit", findings=[
        RiskFinding(owasp_id="MCP03", title="x", severity=Severity.CRITICAL, description=""),
    ])
    assert 0 < low.compute_score() < critical.compute_score() <= 100


def test_fingerprint_dim_is_derived() -> None:
    fp = Fingerprint(vector=[0.1, 0.2, 0.3], model="test")
    assert fp.dim == 3


def test_threat_content_hash_is_normalized() -> None:
    a = Threat(text="Ignore Previous Instructions ")
    b = Threat(text="ignore previous instructions")
    assert a.content_hash == b.content_hash


def test_owasp_catalog_has_ten_unique_ids() -> None:
    ids = [r.id for r in OWASP_MCP_TOP_10]
    assert len(ids) == 10
    assert len(set(ids)) == 10
    assert get_owasp_risk("MCP01").title
