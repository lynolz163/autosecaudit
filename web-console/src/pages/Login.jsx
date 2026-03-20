import { useState } from "react";

import LanguageSwitcher from "../components/LanguageSwitcher";
import { useI18n } from "../i18n";

const LOGIN_FORM = {
  username: "",
  password: "",
};

const BOOTSTRAP_FORM = {
  bootstrap_token: "",
  username: "",
  display_name: "",
  password: "",
};

export default function Login({ authStatus, message, onLogin, onBootstrap }) {
  const { t } = useI18n();
  const [loginForm, setLoginForm] = useState(LOGIN_FORM);
  const [bootstrapForm, setBootstrapForm] = useState(BOOTSTRAP_FORM);
  const [isSubmitting, setIsSubmitting] = useState(false);

  function updateLoginField(event) {
    const { name, value } = event.target;
    setLoginForm((current) => ({ ...current, [name]: value }));
  }

  function updateBootstrapField(event) {
    const { name, value } = event.target;
    setBootstrapForm((current) => ({ ...current, [name]: value }));
  }

  async function handleLogin(event) {
    event.preventDefault();
    setIsSubmitting(true);
    await onLogin(loginForm);
    setIsSubmitting(false);
  }

  async function handleBootstrap(event) {
    event.preventDefault();
    setIsSubmitting(true);
    await onBootstrap(bootstrapForm);
    setIsSubmitting(false);
  }

  const canBootstrap = Boolean(authStatus?.bootstrap_enabled);
  const needsBootstrap = authStatus && !authStatus.has_users;

  return (
    <div className="login-shell">
      <section className="login-hero">
        <div className="login-hero-toolbar">
          <p className="eyebrow">{t("login.heroEyebrow")}</p>
          <LanguageSwitcher />
        </div>
        <h1>{t("login.heroTitle")}</h1>
        <p className="hero-copy">{t("login.heroCopy")}</p>
      </section>

      <div className="mx-auto max-w-xl">
        {needsBootstrap ? (
          <section className="panel">
            <div className="panel-head">
              <div>
                <p className="eyebrow">{t("login.bootstrapEyebrow")}</p>
                <h3>{t("login.bootstrapTitle")}</h3>
              </div>
            </div>
            {canBootstrap ? (
              <form className="scan-form" onSubmit={handleBootstrap}>
                <label>
                  <span>{t("login.bootstrapToken")}</span>
                  <input
                    name="bootstrap_token"
                    type="password"
                    value={bootstrapForm.bootstrap_token}
                    onChange={updateBootstrapField}
                    placeholder="AUTOSECAUDIT_WEB_API_TOKEN"
                    required
                  />
                </label>
                <label>
                  <span>{t("common.username")}</span>
                  <input
                    name="username"
                    value={bootstrapForm.username}
                    onChange={updateBootstrapField}
                    placeholder={t("login.usernamePlaceholder")}
                    required
                  />
                </label>
                <label>
                  <span>{t("common.displayName")}</span>
                  <input
                    name="display_name"
                    value={bootstrapForm.display_name}
                    onChange={updateBootstrapField}
                    placeholder={t("login.displayNamePlaceholder")}
                  />
                </label>
                <label>
                  <span>{t("common.password")}</span>
                  <input
                    name="password"
                    type="password"
                    value={bootstrapForm.password}
                    onChange={updateBootstrapField}
                    placeholder={t("login.minimumPassword")}
                    required
                  />
                </label>
                <button className={`primary-button ${isSubmitting ? "is-loading" : ""}`} type="submit" disabled={isSubmitting}>
                  {isSubmitting ? t("login.creating") : t("login.createFirstAdmin")}
                </button>
                {message ? <div className="error-toast">{message}</div> : null}
                <div className="table-meta">
                  {t("login.bootstrapDisabled")}
                </div>
              </form>
            ) : (
              <div className="empty-state">{t("login.bootstrapDisabled")}</div>
            )}
          </section>
        ) : (
          <section className="panel">
            <div className="panel-head">
              <div>
                <p className="eyebrow">{t("login.signInEyebrow")}</p>
                <h3>{t("login.signInTitle")}</h3>
              </div>
            </div>
            <form className="scan-form" onSubmit={handleLogin}>
              <label>
                <span>{t("common.username")}</span>
                <input
                  name="username"
                  value={loginForm.username}
                  onChange={updateLoginField}
                  placeholder={t("login.usernamePlaceholder")}
                  required
                />
              </label>
              <label>
                <span>{t("common.password")}</span>
                <input
                  name="password"
                  type="password"
                  value={loginForm.password}
                  onChange={updateLoginField}
                  placeholder={t("login.passwordPlaceholder")}
                  required
                />
              </label>
              <button className={`primary-button ${isSubmitting ? "is-loading" : ""}`} type="submit" disabled={isSubmitting}>
                {isSubmitting ? t("login.authenticating") : t("login.signIn")}
              </button>
              {message ? <div className="error-toast">{message}</div> : null}
            </form>
            <div className="mt-4 rounded-[24px] border border-slate-200 bg-slate-50/80 px-4 py-3 text-sm leading-6 text-slate-500">
              {t("login.accountExists")}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}
