import { useEffect, useState } from "react";
import { useI18n } from "../i18n";

const FALLBACK_PRESETS = [
  { id: "openai", label: "OpenAI" },
  { id: "qwen", label: "Qwen" },
  { id: "deepseek", label: "DeepSeek" },
  { id: "glm", label: "GLM" },
  { id: "kimi", label: "Kimi" },
  { id: "siliconflow", label: "SiliconFlow" },
  { id: "ollama", label: "Ollama" },
  { id: "custom", label: "Custom" },
];

export default function LlmConfigPanel({ llmSettings, onSave, onTest }) {
  const { t, language } = useI18n();
  const presets = Array.isArray(llmSettings?.presets) && llmSettings.presets.length ? llmSettings.presets : FALLBACK_PRESETS;
  const [selectedPreset, setSelectedPreset] = useState(llmSettings?.preset_id || "");
  const [baseUrl, setBaseUrl] = useState(llmSettings?.base_url || "");
  const [model, setModel] = useState(llmSettings?.model || "");
  const [apiKey, setApiKey] = useState("");
  const [temperature, setTemperature] = useState(llmSettings?.temperature ?? 0);
  const [maxTokens, setMaxTokens] = useState(llmSettings?.max_output_tokens ?? 1200);
  const [timeout, setTimeoutSeconds] = useState(llmSettings?.timeout_seconds ?? 300);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState(null);

  useEffect(() => {
    if (!llmSettings) {
      return;
    }
    setSelectedPreset(llmSettings.preset_id || "");
    setBaseUrl(llmSettings.base_url || "");
    setModel(llmSettings.model || "");
    setTemperature(llmSettings.temperature ?? 0);
    setMaxTokens(llmSettings.max_output_tokens ?? 1200);
    setTimeoutSeconds(llmSettings.timeout_seconds ?? 300);
  }, [llmSettings?.preset_id, llmSettings?.base_url, llmSettings?.model, llmSettings?.temperature, llmSettings?.max_output_tokens, llmSettings?.timeout_seconds]);

  function selectPreset(presetId) {
    setSelectedPreset(presetId);
    setTestResult(null);
    const preset = presets.find((item) => item.id === presetId);
    if (!preset) {
      return;
    }
    if (preset.base_url !== undefined) {
      setBaseUrl(preset.base_url || "");
    }
    if (preset.default_model !== undefined) {
      setModel(preset.default_model || "");
    }
  }

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await onTest({
        provider_type: "openai_compatible",
        base_url: baseUrl,
        model,
        api_key: apiKey || undefined,
        timeout_seconds: timeout,
      });
      setTestResult(result);
    } finally {
      setTesting(false);
    }
  }

  async function handleSave(event) {
    event.preventDefault();
    setSaving(true);
    try {
      await onSave({
        preset_id: selectedPreset || null,
        provider_type: "openai_compatible",
        base_url: baseUrl,
        model,
        api_key: apiKey || undefined,
        temperature,
        max_output_tokens: maxTokens,
        timeout_seconds: timeout,
      });
    } finally {
      setSaving(false);
    }
  }

  const sourceLabel =
    llmSettings?.source === "web"
      ? t("llm.sourceWeb")
      : llmSettings?.source === "env"
        ? t("llm.sourceEnv")
        : t("llm.sourceNone");
  const selectedPresetMeta = presets.find((item) => item.id === selectedPreset);

  return (
    <form className="panel" onSubmit={handleSave}>
      <div className="panel-head">
        <div>
          <p className="eyebrow">{t("llm.eyebrow")}</p>
          <h3>{t("llm.title")}</h3>
        </div>
        <span className="panel-chip">{sourceLabel}</span>
      </div>

      <div className="llm-presets">
        {presets.map((preset) => (
          <button
            key={preset.id}
            type="button"
            className={`llm-preset-btn${selectedPreset === preset.id ? " is-active" : ""}`}
            onClick={() => selectPreset(preset.id)}
          >
            <span className="llm-preset-label">{preset.label}</span>
          </button>
        ))}
      </div>

      {selectedPresetMeta?.note ? <div className="llm-preset-note">{selectedPresetMeta.note}</div> : null}

      <div className="field-grid">
        <label>
          <span>{t("llm.baseUrl")}</span>
          <input value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="https://api.openai.com/v1" required />
        </label>
        <label>
          <span>{t("llm.model")}</span>
          <input value={model} onChange={(event) => setModel(event.target.value)} placeholder="gpt-4.1-mini" required />
        </label>
      </div>

      <label>
        <span>{t("llm.apiKey")}</span>
        <input
          type="password"
          value={apiKey}
          onChange={(event) => setApiKey(event.target.value)}
          placeholder={llmSettings?.api_key_configured ? t("llm.apiKeyConfigured") : t("llm.apiKeyPlaceholder")}
        />
      </label>

      <button className="ghost-button mt-2" type="button" onClick={() => setShowAdvanced((current) => !current)}>
        {showAdvanced
          ? language === "zh-CN"
            ? "收起高级配置"
            : "Hide advanced settings"
          : language === "zh-CN"
            ? "展开高级配置"
            : "Show advanced settings"}
      </button>

      {showAdvanced ? (
        <div className="field-grid mt-2">
          <label>
            <span>{t("llm.temperature")}</span>
            <input type="number" min="0" max="2" step="0.1" value={temperature} onChange={(event) => setTemperature(Number(event.target.value))} />
          </label>
          <label>
            <span>{t("llm.maxTokens")}</span>
            <input type="number" min="1" max="65536" value={maxTokens} onChange={(event) => setMaxTokens(Number(event.target.value))} />
          </label>
          <label>
            <span>{t("llm.timeout")}</span>
            <input type="number" min="3" max="600" value={timeout} onChange={(event) => setTimeoutSeconds(Number(event.target.value))} />
          </label>
        </div>
      ) : null}

      {testResult ? (
        <div className={`llm-test-result ${testResult.ok ? "is-ok" : "is-error"}`}>
          {testResult.ok ? (
            <>
              {language === "zh-CN" ? "连接成功" : "Connection succeeded"} | {testResult.latency_ms}ms
              {testResult.reply_preview ? <span className="llm-test-reply"> | {testResult.reply_preview}</span> : null}
            </>
          ) : (
            <>{testResult.error}</>
          )}
        </div>
      ) : null}

      <div className="inline-actions mt-3">
        <button type="button" className="ghost-button" onClick={handleTest} disabled={testing || !baseUrl || !model}>
          {testing ? t("llm.testing") : t("llm.testConnection")}
        </button>
        <button type="submit" className="primary-button" disabled={saving || !baseUrl || !model}>
          {saving ? t("llm.saving") : t("llm.saveConfig")}
        </button>
      </div>
    </form>
  );
}
