# Cache diagram

`resources.mmd` describes fetches and cache use. The architecture page embeds its SVG so the page needs no client diagram library or network request. The main architecture diagram is the `ArchitectureDiagram` component.

Regenerate with Mermaid CLI 12.2.0 from `docs/`:

```sh
npx --yes @mermaid-js/mermaid-cli@12.2.0 \
  --input src/assets/diagrams/resources.mmd \
  --output src/assets/diagrams/resources.svg \
  --configFile src/assets/diagrams/mermaid.config.json \
  --svgId trowl-resources \
  --backgroundColor transparent
```

Use `--puppeteerConfigFile` to select an existing Chromium installation when needed. Colours inherit the docs theme. Diagram text uses the site's system font stack.

Keep fetches before their consumers. The implementation fetches NVD before matching, KEV and EPSS after kernel assessment, and model weights before the local summary. `--no-network` disables NVD refreshes and skips KEV, EPSS and advisory links. It does not disable model downloads on a cache miss.
