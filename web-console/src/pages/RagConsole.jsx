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
    setCorpusMessage(language === "zh-CN" ? "Loading knowledge base..." : "Loading knowledge base...");
    try {
      const payload = await apiFetch("/api/v1/rag/corpus", { token });
      setCorpusMeta(payload);
      setDocsInput(JSON.stringify(Array.isArray(payload.documents) ? payload.documents : [], null, 2));
      setCorpusMessage(language === "zh-CN" ? "Knowledge base loaded" : "Knowledge base loaded");
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

  const handleSaveCorpus = async (event) => {
    event.preventDefault();
    let documents = [];
    try {
      const parsed = JSON.parse(docsInput || "[]");
      if (!Array.isArray(parsed)) throw new Error("documents must be a JSON array");
      documents = parsed;
    } catch (err) {
      setCorpusMessage(`Parse Error: ${err.message}`);
      return;
    }

    setSavingCorpus(true);
    setCorpusMessage("Saving knowledge base...");
    try {
      await apiFetch("/api/v1/rag/corpus", {
        method: "PUT",
        token,
        body: JSON.stringify({ documents }),
      });
      await loadCorpus();
      setCorpusMessage("Knowledge base saved and reindexed");
    } catch (err) {
      setCorpusMessage(String(err.message || err));
    } finally {
      setSavingCorpus(false);
    }
  };

  const handleSearch = async (event) => {
    event.preventDefault();
    setSearching(true);
    setSearchMessage("Searching knowledge base...");

    const techStack = searchParams.tech_stack
      .split(",")
      .map((item) => item.trim())
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
      setSearchMessage(`${payload.items?.length || 0} hit(s)`);
    } catch (err) {
      setSearchMessage(String(err.message || err));
    } finally {
      setSearching(false);
    }
  };

  const updateSearchParam = (event) => {
    const { name, value, type } = event.target;
    setSearchParams((prev) => ({
      ...prev,
      [name]: type === "number" ? Number(value) : value,
    }));
  };

  return (
    <div className="page-grid rag-console-layout">
      <section className="panel field-span-2">
        <div className="panel-head">
          <div>
            <p className="eyebrow">Enterprise Knowledge</p>
            <h3>Knowledge-backed auditing</h3>
          </div>
          <div className="inline-actions">
            <button className="ghost-button" onClick={loadCorpus} disabled={loadingCorpus}>
              Reload corpus
            </button>
          </div>
        </div>
        <div className="table-meta">
          Upload architecture notes, runbooks, swagger excerpts, or internal findings so the agent can audit with business context.
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">Corpus Metadata</p>
            <h3>Status</h3>
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
          <div className="empty-state">No metadata loaded.</div>
        )}

        <form className="mt-6" onSubmit={handleSaveCorpus}>
          <label className="grid gap-2">
            <span>Documents JSON (inline array)</span>
            <textarea
              value={docsInput}
              onChange={(event) => setDocsInput(event.target.value)}
              rows={15}
              spellCheck={false}
              className="mono min-h-[400px] w-full resize-y"
            />
          </label>
          <div className="inline-actions mt-4">
            <span className="adv-status mr-auto self-center text-sm text-slate-400">
              {corpusMessage}
            </span>
            <button type="submit" className="primary-button" disabled={savingCorpus || loadingCorpus}>
              Save and reindex
            </button>
          </div>
        </form>
      </section>

      <section className="panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">Search Sandbox</p>
            <h3>Test retrieval quality</h3>
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
          <label className="field-span-2">
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
          <div className="inline-actions field-span-2 mt-2">
            <span className="adv-status mr-auto self-center text-sm text-slate-400">
              {searchMessage}
            </span>
            <button type="submit" className="primary-button" disabled={searching}>
              Execute search
            </button>
          </div>
        </form>

        <div className="table-list mt-6">
          <div className="table-header rag-result-row">
            <div className="table-title">Snippets</div>
            <div className="table-meta">Confidence</div>
            <div className="table-meta">Doc ID / Tool</div>
          </div>
          {!searchResults ? (
            <div className="empty-state">Ready</div>
          ) : searchResults.length === 0 ? (
            <div className="empty-state">No exact matches.</div>
          ) : (
            searchResults.map((hit, index) => (
              <div className="table-row rag-result-row !items-start !p-4" key={index}>
                <div className="rag-snippet-cell">
                  <strong className="mb-1 block text-slate-900">{hit.title || hit.doc_id || "Untitled"}</strong>
                  <div className="rag-snippet-text">{hit.snippet || hit.summary || "-"}</div>
                </div>
                <div className="table-meta cvss-score text-urgent font-semibold">
                  {Number(hit.score || 0).toFixed(2)}
                </div>
                <div className="table-meta flex flex-col gap-2">
                  <span className="cve-badge is-muted">{hit.doc_id || "-"}</span>
                  {hit.recommended_tools && hit.recommended_tools.map((tool) => (
                    <span className="cve-badge is-pending" key={tool}>{tool}</span>
                  ))}
                  {hit.references && hit.references.slice(0, 2).map((href, indexRef) => (
                    <a href={href} key={indexRef} target="_blank" rel="noreferrer" className="text-xs text-sky-600 hover:text-sky-700">[Ref {indexRef + 1}]</a>
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


