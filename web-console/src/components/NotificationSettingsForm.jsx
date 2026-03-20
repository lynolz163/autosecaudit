import { useEffect, useState } from "react";
import { useI18n } from "../i18n";

const EVENT_OPTIONS = [
  { id: "completed", zh: "任务完成", en: "Job completed" },
  { id: "failed", zh: "任务失败", en: "Job failed" },
  { id: "error", zh: "运行异常", en: "Runtime error" },
  { id: "canceled", zh: "任务取消", en: "Job canceled" },
  { id: "finding_high", zh: "发现高危漏洞", en: "High finding detected" },
  { id: "finding_critical", zh: "发现严重漏洞", en: "Critical finding detected" },
];

const CHANNELS = [
  {
    id: "webhook",
    type: "webhook",
    titleZh: "通用 Webhook",
    titleEn: "Generic Webhook",
    fields: [
      { key: "webhook_url", labelZh: "Webhook 地址", labelEn: "Webhook URL", placeholder: "https://example.com/hook" },
      { key: "gateway_base_url", labelZh: "网关地址（可选）", labelEn: "Gateway URL (optional)", placeholder: "https://gateway.internal" },
    ],
  },
  {
    id: "dingtalk",
    type: "dingtalk",
    titleZh: "钉钉机器人",
    titleEn: "DingTalk Robot",
    fields: [
      { key: "webhook_url", labelZh: "机器人 Webhook", labelEn: "Robot Webhook", placeholder: "https://oapi.dingtalk.com/robot/send?access_token=..." },
    ],
  },
  {
    id: "wecom",
    type: "wecom",
    titleZh: "企业微信机器人",
    titleEn: "WeCom Robot",
    fields: [
      { key: "webhook_url", labelZh: "机器人 Webhook", labelEn: "Robot Webhook", placeholder: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..." },
    ],
  },
  {
    id: "telegram",
    type: "telegram",
    titleZh: "Telegram",
    titleEn: "Telegram",
    fields: [
      { key: "bot_token", labelZh: "Bot Token", labelEn: "Bot Token", placeholder: "123456:ABCDEF..." },
      { key: "bot_token_env", labelZh: "Bot Token 环境变量（可选）", labelEn: "Bot Token Env (optional)", placeholder: "LYNOLZ_BOT_TOKEN" },
      { key: "chat_id", labelZh: "Chat ID", labelEn: "Chat ID", placeholder: "-1001234567890" },
      { key: "api_base_url", labelZh: "API Base URL（可选）", labelEn: "API Base URL (optional)", placeholder: "https://api.telegram.org" },
    ],
  },
];

function emptyChannelState(channel) {
  const fields = {};
  for (const field of channel.fields) {
    fields[field.key] = "";
  }
  return {
    enabled: false,
    timeout_seconds: 8,
    headers_json: "",
    ...fields,
  };
}

function normalizeConfig(config) {
  const source = typeof config === "object" && config ? config : {};
  const notifiers = typeof source.notifiers === "object" && source.notifiers ? source.notifiers : {};
  const channels = {};
  for (const channel of CHANNELS) {
    const item = typeof notifiers[channel.id] === "object" && notifiers[channel.id] ? notifiers[channel.id] : {};
    channels[channel.id] = {
      ...emptyChannelState(channel),
      ...item,
      enabled: Boolean(item.enabled),
      timeout_seconds: Number(item.timeout_seconds || 8),
      headers_json:
        item.headers && typeof item.headers === "object" && Object.keys(item.headers).length
          ? JSON.stringify(item.headers, null, 2)
          : "",
    };
  }
  return {
    events: Array.isArray(source.events) ? source.events : [],
    channels,
  };
}

function parseHeaders(raw) {
  const text = String(raw || "").trim();
  if (!text) {
    return undefined;
  }
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("headers must be a JSON object");
  }
  return parsed;
}

export default function NotificationSettingsForm({ notificationConfig, onSave }) {
  const { language } = useI18n();
  const isZh = language === "zh-CN";
  const [form, setForm] = useState(() => normalizeConfig(notificationConfig));
  const [error, setError] = useState("");

  useEffect(() => {
    setForm(normalizeConfig(notificationConfig));
    setError("");
  }, [notificationConfig]);

  function toggleEvent(eventId) {
    setForm((current) => ({
      ...current,
      events: current.events.includes(eventId)
        ? current.events.filter((item) => item !== eventId)
        : [...current.events, eventId],
    }));
  }

  function updateChannel(channelId, field, value) {
    setForm((current) => ({
      ...current,
      channels: {
        ...current.channels,
        [channelId]: {
          ...current.channels[channelId],
          [field]: value,
        },
      },
    }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    try {
      setError("");
      const payload = {
        events: form.events,
        notifiers: {},
      };

      for (const channel of CHANNELS) {
        const state = form.channels[channel.id];
        if (!state?.enabled) {
          continue;
        }
        const item = {
          enabled: true,
          type: channel.type,
          name: channel.id,
          timeout_seconds: Number(state.timeout_seconds || 8),
        };
        for (const field of channel.fields) {
          const value = String(state[field.key] || "").trim();
          if (value) {
            item[field.key] = value;
          }
        }
        const headers = parseHeaders(state.headers_json);
        if (headers) {
          item.headers = headers;
        }
        payload.notifiers[channel.id] = item;
      }

      await onSave(payload);
    } catch (saveError) {
      setError(String(saveError.message || saveError));
    }
  }

  return (
    <form className="panel" onSubmit={handleSubmit}>
      <div className="panel-head">
        <div>
          <p className="eyebrow">{isZh ? "通知" : "Notifications"}</p>
          <h3>{isZh ? "自动通知配置" : "Automation Notification Settings"}</h3>
        </div>
      </div>

      <section className="settings-section">
        <div className="settings-section-head">
          <strong>{isZh ? "触发事件" : "Trigger Events"}</strong>
          <span className="table-meta">{isZh ? "选择需要推送的任务状态与发现级别" : "Choose which states and findings should send alerts"}</span>
        </div>
        <div className="checkbox-grid">
          {EVENT_OPTIONS.map((item) => (
            <label key={item.id} className="checkbox-card">
              <input
                type="checkbox"
                checked={form.events.includes(item.id)}
                onChange={() => toggleEvent(item.id)}
              />
              <span>{isZh ? item.zh : item.en}</span>
            </label>
          ))}
        </div>
      </section>

      <div className="channel-grid">
        {CHANNELS.map((channel) => {
          const state = form.channels[channel.id];
          return (
            <section key={channel.id} className="channel-card">
              <div className="toggle-row">
                <div>
                  <strong>{isZh ? channel.titleZh : channel.titleEn}</strong>
                  <div className="table-meta">{channel.type}</div>
                </div>
                <label className="toggle-pill">
                  <input
                    type="checkbox"
                    checked={Boolean(state.enabled)}
                    onChange={(event) => updateChannel(channel.id, "enabled", event.target.checked)}
                  />
                  <span>{state.enabled ? (isZh ? "已启用" : "Enabled") : isZh ? "未启用" : "Disabled"}</span>
                </label>
              </div>

              <div className="settings-grid">
                {channel.fields.map((field) => (
                  <label key={field.key}>
                    <span>{isZh ? field.labelZh : field.labelEn}</span>
                    <input
                      value={state[field.key] || ""}
                      onChange={(event) => updateChannel(channel.id, field.key, event.target.value)}
                      placeholder={field.placeholder}
                    />
                  </label>
                ))}
                <label>
                  <span>{isZh ? "超时（秒）" : "Timeout (sec)"}</span>
                  <input
                    type="number"
                    min="1"
                    max="60"
                    value={state.timeout_seconds || 8}
                    onChange={(event) => updateChannel(channel.id, "timeout_seconds", Number(event.target.value))}
                  />
                </label>
                <label className="field-span-2">
                  <span>{isZh ? "附加请求头（JSON，可选）" : "Extra Headers (JSON, optional)"}</span>
                  <textarea
                    rows={4}
                    value={state.headers_json || ""}
                    onChange={(event) => updateChannel(channel.id, "headers_json", event.target.value)}
                    placeholder='{"X-Notifier-Route":"webhook"}'
                  />
                </label>
              </div>
            </section>
          );
        })}
      </div>

      <div className="inline-actions">
        <button className="primary-button" type="submit">
          {isZh ? "保存通知配置" : "Save Notification Settings"}
        </button>
      </div>
      {error ? <div className="error-toast">{error}</div> : null}
    </form>
  );
}
