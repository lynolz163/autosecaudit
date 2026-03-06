import { useState, useEffect } from "react";
import { useI18n } from "../i18n";
import { apiFetch } from "../lib/api";

export default function RagConsole({ token }) {
    const { language } = useI18n();
    const [corpusMeta, setCorpusMeta] = useState(null);
    const [docsInput, setDocsInput] = useState("[]");
    const [savingCorpus, setSavingCorpus] = useState(false);
    const [loadingCorpus, setLoadingCorpus] = useState(false);
    const [corpusMessage, setCorpusMessage] = useState("");

    const [searchParams, setSearchParams] = useState({
        query: "",
        component: "",
        version: "",
        tech_stack: "",
        max_results: 8,
        min_score: 1.0,
    });
    const [searching, setSearching] = useState(false);
    const [searchResults, setSearchResults] = useState(null);
    const [searchMessage, setSearchMessage] = useState("");

    const loadCorpus = async () => {
        setLoadingCorpus(true);
        setCorpusMessage(language === "zh-CN" ? "加载中..." : "Loading...");
        try {
            const payload = await apiFetch("/api/v1/rag/corpus", { token });
            setCorpusMeta(payload);
            setDocsInput(JSON.stringify(Array.isArray(payload.documents) ? payload.documents : [], null, 2));
            setCorpusMessage(language === "zh-CN" ? "已加载" : "Loaded");
        } catch (err) {
            setCorpusMessage(String(err.message || err));
        } finally {
            setLoadingCorpus(false);
        }
    };

    useEffect(() => {
        if (token) {
            loadCorpus();
        }
    }, [token]);

    const handleSaveCorpus = async (e) => {
        e.preventDefault();
        let documents = [];
        try {
            const parsed = JSON.parse(docsInput || "[]");
            if (!Array.isArray(parsed)) throw new Error("documents must be JSON array");
            documents = parsed;
        } catch (err) {
            setCorpusMessage(language === "zh-CN" ? `解析错误: ${err.message}` : `Parse Error: ${err.message}`);
            return;
        }

        setSavingCorpus(true);
        setCorpusMessage(language === "zh-CN" ? "保存中..." : "Saving...");
        try {
            await apiFetch("/api/v1/rag/corpus", {
                method: "PUT",
                token,
                body: JSON.stringify({ documents }),
            });
            await loadCorpus();
            setCorpusMessage(language === "zh-CN" ? "保存成功" : "Saved successfully");
        } catch (err) {
            setCorpusMessage(String(err.message || err));
        } finally {
            setSavingCorpus(false);
        }
    };

    const handleSearch = async (e) => {
        e.preventDefault();
        setSearching(true);
        setSearchMessage(language === "zh-CN" ? "检索中..." : "Searching...");

        const techStack = searchParams.tech_stack
            .split(",")
            .map(s => s.trim())
            .filter(Boolean);

        try {
            const payload = await apiFetch("/api/v1/rag/search", {
                method: "POST",
                token,
                body: JSON.stringify({
                    query: searchParams.query || null,
                    component: searchParams.component || null,
                    version: searchParams.version || null,
                    tech_stack: techStack.length ? techStack : null,
                    max_results: searchParams.max_results,
                    min_score: searchParams.min_score,
                }),
            });
            setSearchResults(Array.isArray(payload.items) ? payload.items : []);
            setSearchMessage(language === "zh-CN" ? `命中 ${payload.items?.length || 0} 条` : `${payload.items?.length || 0} Hits`);
        } catch (err) {
            setSearchMessage(String(err.message || err));
        } finally {
            setSearching(false);
        }
    };

    const updateSearchParam = (e) => {
        const { name, value, type } = e.target;
        setSearchParams(prev => ({
            ...prev,
            [name]: type === "number" ? Number(value) : value,
        }));
    };

    return (
        <div className="page-grid rag-console-layout">
                <section className="panel" style={{ gridColumn: "1 / -1" }}>
                    <div className="panel-head">
                        <div>
                            <p className="eyebrow">RAG Knowledge Base</p>
                            <h3>{language === "zh-CN" ? "知识库管理与检索调试" : "Corpus & Search Sandbox"}</h3>
                        </div>
                        <div className="inline-actions">
                            <button className="ghost-button" onClick={loadCorpus} disabled={loadingCorpus}>
                                {language === "zh-CN" ? "重新加载语料" : "Reload"}
                            </button>
                        </div>
                    </div>
                </section>

                <section className="panel">
                    <div className="panel-head">
                        <div>
                            <p className="eyebrow">Corpus Metadata</p>
                            <h3>{language === "zh-CN" ? "配置状态" : "Status"}</h3>
                        </div>
                    </div>
                    {corpusMeta ? (
                        <div className="job-detail-grid rag-meta-grid">
                            <div><p className="eyebrow">Corpus Path</p><div className="rag-meta-value">{corpusMeta.corpus_path}</div></div>
                            <div><p className="eyebrow">Exists</p><div className="rag-meta-value">{String(corpusMeta.exists)}</div></div>
                            <div><p className="eyebrow">Writable</p><div className="rag-meta-value">{String(corpusMeta.writable)}</div></div>
                            <div><p className="eyebrow">External Docs</p><div className="rag-meta-value">{corpusMeta.external_document_count || 0}</div></div>
                            <div><p className="eyebrow">Effective Docs</p><div className="rag-meta-value">{corpusMeta.effective_document_count || 0}</div></div>
                        </div>
                    ) : (
                        <div className="empty-state">{language === "zh-CN" ? "暂无元数据" : "No metadata"}</div>
                    )}

                    <form onSubmit={handleSaveCorpus} style={{ marginTop: '24px' }}>
                        <label style={{ display: 'grid', gap: '8px' }}>
                            <span>{language === "zh-CN" ? "Documents JSON (数组，非外部语料可直接编辑)" : "Documents JSON (Inline Array)"}</span>
                            <textarea
                                value={docsInput}
                                onChange={(e) => setDocsInput(e.target.value)}
                                rows={15}
                                spellCheck={false}
                                style={{
                                    width: '100%',
                                    background: '#00000066',
                                    color: 'inherit',
                                    fontFamily: 'JetBrains Mono, monospace',
                                    padding: '12px',
                                    borderRadius: '8px',
                                    border: '1px solid var(--line)',
                                    minHeight: '400px',
                                    resize: 'vertical'
                                }}
                            />
                        </label>
                        <div className="inline-actions" style={{ marginTop: '16px' }}>
                            <span className="adv-status" style={{ marginRight: 'auto', alignSelf: 'center', color: 'var(--muted)', fontSize: '13px' }}>
                                {corpusMessage}
                            </span>
                            <button type="submit" className="primary-button" disabled={savingCorpus || loadingCorpus}>
                                {language === "zh-CN" ? "保存并重建索引" : "Save & Reindex"}
                            </button>
                        </div>
                    </form>
                </section>

                <section className="panel">
                    <div className="panel-head">
                        <div>
                            <p className="eyebrow">Search Demo</p>
                            <h3>{language === "zh-CN" ? "检索沙盒" : "Search Sandbox"}</h3>
                        </div>
                    </div>
                    <form className="field-grid rag-search-grid" onSubmit={handleSearch}>
                        <label>
                            <span>Query</span>
                            <input name="query" value={searchParams.query} onChange={updateSearchParam} placeholder="nginx relative path traversal" />
                        </label>
                        <label>
                            <span>Component</span>
                            <input name="component" value={searchParams.component} onChange={updateSearchParam} placeholder="nginx" />
                        </label>
                        <label>
                            <span>Version</span>
                            <input name="version" value={searchParams.version} onChange={updateSearchParam} placeholder="1.24.0" />
                        </label>
                        <label style={{ gridColumn: "1 / -1" }}>
                            <span>Tech Stack (CSV)</span>
                            <input name="tech_stack" value={searchParams.tech_stack} onChange={updateSearchParam} placeholder="nginx,react" />
                        </label>
                        <label>
                            <span>Max Results</span>
                            <input type="number" name="max_results" value={searchParams.max_results} onChange={updateSearchParam} min="1" max="50" />
                        </label>
                        <label>
                            <span>Min Score</span>
                            <input type="number" name="min_score" value={searchParams.min_score} onChange={updateSearchParam} step="0.1" min="0" max="100" />
                        </label>
                        <div className="inline-actions" style={{ gridColumn: "1 / -1", marginTop: '8px' }}>
                            <span className="adv-status" style={{ marginRight: 'auto', alignSelf: 'center', color: 'var(--muted)', fontSize: '13px' }}>
                                {searchMessage}
                            </span>
                            <button type="submit" className="primary-button" disabled={searching}>
                                {language === "zh-CN" ? "执行检索 RAG" : "Execute Search"}
                            </button>
                        </div>
                    </form>

                    <div className="table-list" style={{ marginTop: '24px' }}>
                        <div className="table-header rag-result-row">
                            <div className="table-title">{language === "zh-CN" ? "匹配段落" : "Snippets"}</div>
                            <div className="table-meta">{language === "zh-CN" ? "得分/置信度" : "Confidence"}</div>
                            <div className="table-meta">Doc ID / Tool</div>
                        </div>
                        {!searchResults ? (
                            <div className="empty-state">{language === "zh-CN" ? "准备就绪" : "Ready"}</div>
                        ) : searchResults.length === 0 ? (
                            <div className="empty-state">{language === "zh-CN" ? "未命中记录" : "No exact matches"}</div>
                        ) : (
                            searchResults.map((hit, idx) => (
                                <div className="table-row rag-result-row" key={idx} style={{ alignItems: 'flex-start', padding: '16px' }}>
                                    <div className="rag-snippet-cell">
                                        <strong style={{ display: 'block', marginBottom: '4px', color: '#fff' }}>{hit.title || hit.doc_id || "Untitled"}</strong>
                                        <div className="rag-snippet-text">{hit.snippet || hit.summary || "-"}</div>
                                    </div>
                                    <div className="table-meta cvss-score text-urgent" style={{ fontWeight: 600 }}>
                                        {Number(hit.score || 0).toFixed(2)}
                                    </div>
                                    <div className="table-meta" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                        <span className="cve-badge is-muted">{hit.doc_id || "-"}</span>
                                        {hit.recommended_tools && hit.recommended_tools.map(tool => (
                                            <span className="cve-badge is-pending" key={tool}>{tool}</span>
                                        ))}
                                        {hit.references && hit.references.slice(0, 2).map((href, i) => (
                                            <a href={href} key={i} target="_blank" rel="noreferrer" style={{ fontSize: '12px' }}>[Ref {i + 1}]</a>
                                        ))}
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </section>
        </div>
    );
}
