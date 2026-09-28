# Vendored fonts

Committed to git so the build stays pure-cargo (no npm/node required).
Source: Google Fonts (SIL Open Font License), latin subset only.

| File | Family | Weight | Used by |
|---|---|---|---|
| poppins-400.woff2 | Poppins | 400 | `--theme-primary-font-family` |
| poppins-700.woff2 | Poppins | 700 | bold primary text |
| goldman-400.woff2 | Goldman | 400 | `--theme-site-name-font-family`, `--theme-panel-header-font-family` |
| goldman-700.woff2 | Goldman | 700 | bold site name / panel headers |
| inconsolata-400.woff2 | Inconsolata | 400 | `--theme-monospace-font-family` |
| inconsolata-500.woff2 | Inconsolata | 500 | `--theme-monospace-font-weight` (Google serves the same file for 400/500) |

The matching `@font-face` rules live in `crates/ui-components/css/fonts.css`.

## Updating a font

Fetch the woff2 from the Google Fonts css2 API with a browser User-Agent,
save it here under the `<family>-<weight>.woff2` naming, and keep
`fonts.css` in sync.
