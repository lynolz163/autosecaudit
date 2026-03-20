/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        chrome: {
          950: "#09090b",
          925: "#0f1115",
          900: "#111318",
          850: "#171a21",
          800: "#1d2230",
          700: "#273042",
        },
      },
      fontFamily: {
        sans: ["Inter", "IBM Plex Sans", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        panel: "0 20px 50px -36px rgba(15, 23, 42, 0.65)",
        subtle: "0 10px 30px -24px rgba(15, 23, 42, 0.55)",
      },
      backdropBlur: {
        xs: "2px",
      },
    },
  },
  plugins: [],
};
