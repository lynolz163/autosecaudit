import { useState, useMemo } from "react";
import { useI18n } from "../i18n";
import { apiFetch, buildAuthedUrl } from "../lib/api";

function CveStatusBadge({ cveId, verifications, hasTemplate, t }) {
    const v = verifications.find((item) => item.cve_id === cveId);

    if (!v) {
        if (!hasTemplate) {
            return <span className="cve-badge is-muted">{t("cvePanel.noTemplate")}</span>;
        }
        return <span className="cve-badge is-pending">{t("cvePanel.statusPending")}</span>;
    }

    if (v.verified) {
        return <span className="cve-badge is-exploitable">{t("cvePanel.statusExploitable")}</span>;
    }

    return <span className="cve-badge is-safe">{t("cvePanel.statusSafe")}</span>;
}

export default function CVEPanel({
    candidates = [],
    verifications = [],
    target,
    token,
    onRefresh
}) {
    const { t } = useI18n();
    const [selectedCves, setSelectedCves] = useState(new Set());
    const [showAuthModal, setShowAuthModal] = useState(false);
    const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [errorObj, setErrorObj] = useState(null);

    const toggleSelection = (cveId) => {
        const next = new Set(selectedCves);
        if (next.has(cveId)) {
            next.delete(cveId);
        } else {
            next.add(cveId);
        }
        setSelectedCves(next);
    };

    const onSelectAll = (e) => {
        if (e.target.checked) {
            setSelectedCves(new Set(candidates.filter(c => c.has_nuclei_template).map(c => c.cve_id)));
        } else {
            setSelectedCves(new Set());
        }
    };

    const handleVerifyRequest = async () => {
        if (!authorizationConfirmed) return;

        setIsSubmitting(true);
        setErrorObj(null);
        try {
            await apiFetch("/api/cve/verify", {
                method: "POST",
                token,
                body: JSON.stringify({
                    target: target || "global",
                    cve_ids: Array.from(selectedCves),
                    authorization_confirmed: true,
                    safe_only: true, // Conservative default
                    allow_high_risk: false,
                }),
            });
            // Verification job launched, clear selection and notify parent to refresh/redirect
            setSelectedCves(new Set());
            setShowAuthModal(false);
            if (onRefresh) onRefresh();
        } catch (err) {
            setErrorObj(err);
        } finally {
            setIsSubmitting(false);
        }
    };

    if (!candidates || candidates.length === 0) {
        return (
            <section className="panel">
                <div className="panel-head">
                    <div>
                        <p className="eyebrow">{t("cvePanel.eyebrow")}</p>
                        <h3>{t("cvePanel.title")}</h3>
                    </div>
                </div>
                <div className="empty-state">{t("cvePanel.noCandidates")}</div>
            </section>
        );
    }

    const allSupportedSelected =
        candidates.filter(c => c.has_nuclei_template).length > 0 &&
        selectedCves.size === candidates.filter(c => c.has_nuclei_template).length;

    return (
        <section className="panel">
            <div className="panel-head">
                <div>
                    <p className="eyebrow">{t("cvePanel.eyebrow")}</p>
                    <h3>{t("cvePanel.title")}</h3>
                </div>
                <div className="inline-actions">
                    <button
                        type="button"
                        className="primary-button cve-verify-btn"
                        disabled={selectedCves.size === 0}
                        onClick={() => setShowAuthModal(true)}
                    >
                        {t("cvePanel.verifyBtn")} ({selectedCves.size})
                    </button>
                </div>
            </div>

            <div className="table-list">
                <div className="table-header">
                    <input
                        type="checkbox"
                        checked={allSupportedSelected}
                        onChange={onSelectAll}
                        className="cve-checkbox"
                    />
                    <div className="table-title">CVE ID</div>
                    <div className="table-meta">CVSS</div>
                    <div className="table-meta">Component</div>
                    <div className="table-meta">Status</div>
                </div>

                {candidates.map((cve) => {
                    const isHighRisk = cve.cvss_score >= 7.0;
                    return (
                        <label
                            key={cve.cve_id}
                            className={`table-row cve-row ${isHighRisk ? 'is-critical' : ''}`}
                        >
                            <input
                                type="checkbox"
                                className="cve-checkbox"
                                disabled={!cve.has_nuclei_template}
                                checked={selectedCves.has(cve.cve_id)}
                                onChange={() => toggleSelection(cve.cve_id)}
                            />
                            <div className="table-title">
                                <strong>
                                    <a
                                        href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                                        target="_blank"
                                        rel="noreferrer"
                                    >
                                        {cve.cve_id}
                                    </a>
                                </strong>
                                <div className="cve-desc-truncate" title={cve.description}>
                                    {cve.description}
                                </div>
                            </div>
                            <div className={`table-meta cvss-score ${isHighRisk ? 'text-urgent' : ''}`}>
                                {cve.cvss_score || '-'} ({cve.severity})
                            </div>
                            <div className="table-meta">
                                {cve.component} {cve.version && `v${cve.version}`}
                            </div>
                            <div className="table-meta">
                                <CveStatusBadge
                                    cveId={cve.cve_id}
                                    verifications={verifications}
                                    hasTemplate={cve.has_nuclei_template}
                                    t={t}
                                />
                            </div>
                        </label>
                    )
                })}
            </div>

            {showAuthModal && (
                <div className="modal-overlay">
                    <div className="modal-dialog">
                        <div className="modal-header">
                            <h3>🚨 {t("cvePanel.authModalTitle")}</h3>
                        </div>
                        <div className="modal-body">
                            <p className="auth-alert-text">
                                {t("cvePanel.authModalText").split("\n").map((line, i) => (
                                    <span key={i}>{line}<br /></span>
                                ))}
                            </p>

                            {errorObj && (
                                <div className="error-banner">
                                    {errorObj.message || errorObj.toString()}
                                </div>
                            )}

                            <label className="auth-checkbox-wrap">
                                <input
                                    type="checkbox"
                                    checked={authorizationConfirmed}
                                    onChange={e => setAuthorizationConfirmed(e.target.checked)}
                                />
                                <span>{t("cvePanel.authCheckbox")}</span>
                            </label>
                        </div>
                        <div className="modal-footer">
                            <button
                                type="button"
                                className="ghost-button"
                                onClick={() => {
                                    setShowAuthModal(false);
                                    setAuthorizationConfirmed(false);
                                }}
                            >
                                {t("cvePanel.cancel")}
                            </button>
                            <button
                                type="button"
                                className="danger-button"
                                disabled={!authorizationConfirmed || isSubmitting}
                                onClick={handleVerifyRequest}
                            >
                                {isSubmitting ? t("cvePanel.verifying") : t("cvePanel.confirm")}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </section>
    );
}
