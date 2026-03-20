import { useI18n } from "../i18n";

export default function LanguageSwitcher({ compact = false }) {
  const { language, setLanguage, t } = useI18n();
  const baseButton = "rounded-full px-3 py-1.5 text-xs font-medium transition-all duration-200";
  const activeButton = "bg-slate-950 text-white shadow-[0_12px_22px_-18px_rgba(15,23,42,0.35)]";
  const idleButton = "text-slate-500 hover:bg-white hover:text-slate-900";

  return (
    <div
      className={`inline-flex items-center gap-1 rounded-full border border-white/80 bg-white/80 p-1 shadow-[0_14px_30px_-24px_rgba(15,23,42,0.18)] backdrop-blur-xl ${compact ? "w-fit" : ""}`}
      role="group"
      aria-label={t("language.ariaLabel")}
    >
      <button
        type="button"
        className={`${baseButton} ${language === "zh-CN" ? activeButton : idleButton}`}
        onClick={() => setLanguage("zh-CN")}
      >
        {t("language.zhCNShort")}
      </button>
      <button
        type="button"
        className={`${baseButton} ${language === "en" ? activeButton : idleButton}`}
        onClick={() => setLanguage("en")}
      >
        {t("language.englishShort")}
      </button>
    </div>
  );
}
