# Sigma Rule Builder

A static, browser-based tool for writing, validating, and exporting [Sigma](https://github.com/SigmaHQ/sigma) detection rules — no backend, no account required.

**[→ Open the tool](https://arrogance7705.github.io/sigma-builder/)**

---

## Features

### Guided New Rule Wizard
Click **+ new** to open a step-by-step wizard:
1. **Scenario** — pick a detection scenario (process execution, network, file system, registry, auth, cloud, Linux, or blank)
2. **Basics** — title, severity level, author, optional description (AI-assisted if configured)
3. **Logsource** — filtered logsource cards relevant to your scenario, with AI suggestion
4. **Review** — live YAML preview before you start editing

### Structured Form Editor
Five focused tabs, always visible in the toolbar:

| Tab | What you edit |
|-----|--------------|
| **metadata** | Title, ID, status, level, description, author, references, false positives |
| **logsource** | Category / product / service with quick presets and field suggestions |
| **detection** | Field-value groups (with modifiers), keyword groups, condition builder |
| **tags** | Full-width MITRE ATT&CK Enterprise matrix (v14.1) — click to tag |
| **preview** | Live YAML output, lint errors, copy/export |

Each tab has a status dot: 🟢 ok · 🟡 warning · 🔴 error

### Live Validation
The toolbar badge shows validation state at a glance. The Preview tab shows all errors and warnings inline.

### MITRE ATT&CK Matrix
Full-width interactive matrix covering all 14 tactics and ~200+ techniques. Features:
- Click to select / deselect techniques and sub-techniques
- Search to filter
- Expand sub-technique rows per-technique or show all
- Right-click context menu: select subs, copy T-IDs, copy Sigma tags, open on MITRE site

### Community Rule Browser
Browse and load rules from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) directly — fetched on demand from the GitHub API, no data bundled. Right-click any file to open raw or on GitHub.

### Local Templates
Nine pinned templates included:

| Template | Logsource |
|----------|-----------|
| Suspicious PowerShell | Sysmon process_creation |
| LOLBAS Proxy Execution | Sysmon process_creation |
| Sysmon Network C2 | Sysmon network_connection |
| Defender Malware Alert | Windows Defender |
| Defender Service Disabled | Windows Defender |
| Linux Reverse Shell | Linux auditd |
| Linux sudo Abuse | Linux auditd |
| DNS DGA Activity | DNS |
| DNS Tunneling | DNS |

### AI Augmentation (optional)

Connect any OpenAI-compatible endpoint (LM Studio, Ollama, OpenAI, etc.) in **Settings ⚙**:

| Where | Button | What it does |
|-------|--------|--------------|
| Description field | ✨ | Generates a 2–4 sentence description, streams live |
| False Positives field | ✨ | Brainstorms FP scenarios as chips — add individually or all at once |
| Tags tab | ✨ suggest tags | Suggests ATT&CK T-IDs as clickable chips |
| Preview tab | ✨ explain | Explains what the rule detects in markdown |
| Preview tab | ✨ review | Annotates the YAML with highlighted sections + score |
| New wizard | ✨ | Generates description and suggests logsource during rule creation |

Streaming is preferred; falls back automatically to single-shot if the endpoint doesn't support SSE.

Settings are stored in `localStorage` only — nothing is ever sent anywhere except your configured endpoint.

### Import / Export
- **Import**: paste any existing Sigma YAML to edit it
- **Export**: download a `.yml` file named after the rule title
- **Copy YAML**: one click to clipboard (also available via right-click on the preview)

---

## Usage

Open `index.html` in any modern browser — or use the hosted version at:

```
https://arrogance7705.github.io/sigma-builder/
```

No build step. No npm. No server required.

---

## AI Setup

1. Click **⚙** in the toolbar
2. Set **AI Endpoint URL** — e.g. `http://localhost:1234/v1` for LM Studio
3. Set **Model** — e.g. `qwen/qwen2.5-7b-instruct`
4. Optionally set an **API Key** (required for OpenAI; leave blank for local)
5. Click **Test connection** to verify
6. Click **Save**

The ✨ buttons will activate across the tool once configured.

---

## GitHub Token (optional)

Without a token, the GitHub API allows 60 requests/hour. For heavy community rule browsing, add a token in Settings:

1. [Generate a token](https://github.com/settings/tokens/new?description=sigma-builder&scopes=) — no scopes needed (public repos are readable without any scope)
2. Paste it in **Settings ⚙ → GitHub Personal Access Token**

The token is stored in `localStorage` and only ever sent to `api.github.com`.

---

## Structure

```
sigma-builder/
├── index.html              # App shell + Vue templates
├── css/style.css           # Design system + component styles
├── js/
│   ├── app.js              # Vue 3 app — state, logic, wizard
│   ├── ai.js               # AI client (streaming + fallback)
│   ├── attack-matrix.js    # MITRE ATT&CK data (tactics + techniques)
│   └── sigma-data.js       # Logsources, modifiers, templates catalog
└── templates/              # Pinned YAML templates
    ├── sysmon-suspicious-powershell.yml
    ├── sysmon-lolbas-proxy.yml
    └── ...
```

---

## Design

- Dark minimal aesthetic — `#080808` background, Space Grotesk + Space Mono
- Pure client-side: Vue 3 via CDN, js-yaml via CDN
- No tracking, no cookies, no analytics
- Works offline once loaded (except community browser + AI endpoint)

---

## License

MIT
