/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.html",
    "./static/js/**/*.js",
  ],
  // The six phase-accent classes are applied via a Jinja variable whose
  // values live in core/unlock.py (PHASE_META[...]["css_class"]), not in
  // any file the content glob above scans, so the JIT purge would
  // otherwise drop every .nen-pN / .nen-finals rule. Safelist them
  // explicitly so they always survive the build.
  safelist: [
    "nen-p1",
    "nen-p2",
    "nen-p3",
    "nen-p4",
    "nen-p5",
    "nen-finals",
  ],
  theme: {
    extend: {
      colors: {
        ink: {
          DEFAULT: "#0a0b10",
          soft: "#12141c",
          line: "#1c1f2a",
        },
        bone: "#e8e4da",
        muted: "#9a9aa6",
        brass: "#c9a875",
        nen: {
          p1: "#e5484d",
          p2: "#8b5cf6",
          p3: "#f5c518",
          p4: "#22c55e",
          p5: "#6366f1",
          finals: "#22d3ee",
        },
      },
      fontFamily: {
        display: ["Rajdhani", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["'IBM Plex Mono'", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      keyframes: {
        "ren-pulse": {
          "0%, 100%": { boxShadow: "0 0 0 0 var(--nen-glow, rgba(197,72,77,.35))" },
          "50%": { boxShadow: "0 0 0 10px rgba(0,0,0,0)" },
        },
        "burst": {
          "0%": { transform: "scale(.2)", opacity: "0" },
          "12%": { opacity: "1" },
          "100%": { transform: "scale(2.6)", opacity: "0" },
        },
        "flicker": {
          "0%, 100%": { opacity: "1" },
          "92%": { opacity: "1" },
          "93%": { opacity: ".72" },
          "94%": { opacity: "1" },
        },
      },
      animation: {
        "ren-pulse": "ren-pulse 2.6s ease-in-out infinite",
        "burst": "burst 1.8s cubic-bezier(.2,.8,.3,1) infinite",
        "flicker": "flicker 6s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
