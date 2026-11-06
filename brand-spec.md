# AIGIS — Brand & Design System Specification
Documented per `web-design-engineer` Protocol.

## 1. Identity & Narrative
- **Brand Name**: AIGIS
- **Acronym**: **A**dversarial **I**ntelligence for **G**enerative **I**mmunity & **S**ecurity
- **Tagline**: Evaluating what works at AI’s frontier
- **Core Mission**: Autonomous dual-agent red-team & blue-team proving ground evaluating and securing business logic vulnerabilities (BLVs) in FinTech & E-commerce.
- **Visual School Anchor**: Kaggle Notebooks / Scientific Proving Ground (Kaggle Code Workspace + Builder SaaS Precision).

---

## 2. Design Calibration (Five Dials)
```yaml
Design Read:
  artifact: interactive-code-notebook-proving-ground
  audience: AI practitioners, security researchers, benchmark climbers, Kaggle practitioners
  visual-language: Kaggle Notebooks / Scientific Proving Ground
  mode: overhaul
  visual-variance: 6      # Balanced restraint, focused contrast
  motion-intensity: 4      # Snappy 150-250ms feedback, cell-by-cell execution flow
  information-density: 9  # High code & telemetry density with clean visual hierarchy
  asset-dependence: 6     # Reconstructed state machine, vector typography, live code cells
  brand-fidelity: 10      # 100% adherence to authentic Kaggle Code environment
```

---

## 3. Four Positioning Questions
1. **Narrative Role**: 
   - *Hero*: High-altitude, scientific inspiration ("Evaluating what works at AI's frontier").
   - *Workbench*: Real-time adversarial proving ground where autonomous agents compete and self-heal.
2. **Viewing Distance**: 1m desktop/laptop display (optimized for 1280px - 1920px viewports).
3. **Visual Temperature**: Crisp, airy, authoritative, scientific.
4. **Capacity Check**: Symmetrical 2-column competitor grid, 4-tab workspace, floating Tweaks panel, and modal drawer.

---

## 4. Color Tokens (OKLCH Harmonized)
| Token | Value | Role |
| :--- | :--- | :--- |
| `--canvas-bg` | `#FFFFFF` | Primary white canvas |
| `--surface-bg` | `#F8FAFC` | Subtle off-white proving ground background |
| `--surface-card` | `#FFFFFF` | Pure white card surfaces with 1px border |
| `--text-primary` | `#0F172A` | Slate-900 (deep ink, high legibility) |
| `--text-secondary` | `#475569` | Slate-600 (descriptive subtitles) |
| `--text-muted` | `#94A3B8` | Slate-400 (metadata, timestamps) |
| `--border-hairline` | `#E2E8F0` | 1px subtle boundary divider |
| `--border-hover` | `#CBD5E1` | Interactive card hover border |
| `--brand-black` | `#111827` | Primary action button / Pill CTA |
| `--accent-sky` | `#0284C7` | Benchmark badge text (`#E0F2FE` background) |
| `--accent-cyan` | `#20BEFF` | Kaggle brand cyan accent |
| `--red-threat` | `#E11D48` | Red-team Cerebrus indicators (`#FFF1F2` background) |
| `--blue-immunity` | `#059669` | Blue-team Aegis mitigation indicators (`#ECFDF5` background) |

---

## 5. Typography Scheme
- **Display & Headings**: `'Plus Jakarta Sans'`, `'Google Sans'`, -apple-system, sans-serif
  - `h1`: `clamp(2.25rem, 4.5vw, 3.5rem)`, `font-weight: 600`, `letter-spacing: -0.035em`, `line-height: 1.15`
  - `h2`: `1.25rem`, `font-weight: 700`, `letter-spacing: -0.02em`
  - `h3`: `0.9375rem`, `font-weight: 700`
- **Body Text**: `'Inter'`, -apple-system, sans-serif
  - Subtitle: `1.0625rem`, `font-weight: 400`, `color: #475569`, `line-height: 1.6`
  - Small: `0.8125rem`
- **Code & Numeric Data**: `'JetBrains Mono'`, monospace
  - Currency, stream rates, timestamps, hash identifiers, JSON logs, Git diffs.

---

## 6. Layout & Spatial Geometry
- **Grid**: 8pt base spatial unit (`8px`, `16px`, `24px`, `32px`, `48px`, `64px`).
- **Radius Grammar**:
  - `rounded-full` (`9999px`): Action CTAs, pill tabs, search trigger, status tags.
  - `rounded-2xl` (`16px` - `20px`): Cards, mountain canvas, code panels.
  - `rounded-xl` (`12px`): Inner stat tiles, log viewports.
- **Shadow Scale**:
  - `shadow-xs`: `0 1px 2px 0 rgba(0, 0, 0, 0.03)`
  - `shadow-sm`: `0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.05)`
  - `shadow-floating`: `0 12px 30px -4px rgba(0, 0, 0, 0.08)`
  - `shadow-panel`: `0 20px 40px -8px rgba(0, 0, 0, 0.15)`

---

## 7. Anti-Cliché Rules Applied
1. **No Purple-Pink Gradients**: Zero synthetic AI gradient slop. Pure white and warm mountain sunlight.
2. **No Emoji as Icons**: All iconography is vector SVG (FontAwesome 6 + custom SVG).
3. **No Colored Left-Border Cards**: Clean all-around hairline borders (`1px solid #E2E8F0`).
4. **No Dummy Trust Claims**: Real vector brandmarks for academic and research organizations evaluating on AIGIS.
5. **No Blind Inter Defaults**: Display headings upgraded to world-class `'Plus Jakarta Sans'` with custom kerning.
6. **No Filler Text**: All text directly reflects the active wargame scenario (Tet 2026 Voucher TOCTOU race condition).
