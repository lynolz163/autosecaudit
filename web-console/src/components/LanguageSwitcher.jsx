import { useI18n } from "../i18n";

export default function LanguageSwitcher({ compact = false }) {
  const { language, setLanguage, t } = useI18n();

  return (
    <div className={compact ? "lang-switcher lang-switcher-compact" : "lang-switcher"} role="group" aria-label={t("language.ariaLabel")}>
      <button
        type="button"
        className={language === "zh-CN" ? "lang-button is-active" : "lang-button"}
        onClick={() => setLanguage("zh-CN")}
      >
        {t("language.zhCNShort")}
      </button>
      <button
        type="button"
        className={language === "en" ? "lang-button is-active" : "lang-button"}
        onClick={() => setLanguage("en")}
      >
        {t("language.englishShort")}
      </button>
    </div>
  );
}
