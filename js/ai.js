// ai.js — SigmaAI helper for the Sigma Rule Builder
// Exposes window.SigmaAI with config, prompts, streaming runner, and utilities.

(function () {
  'use strict';

  const STORAGE_KEY = 'sigma_ai_config';

  // ── Endpoint normalizer ───────────────────────────────────────────────────

  function normalizeEndpoint(raw) {
    if (!raw || !raw.trim()) return '';
    let s = raw.trim();
    // 1. Prepend http:// if no protocol
    if (!/^https?:\/\//.test(s)) {
      s = 'http://' + s;
    }
    // 2. Trim trailing slashes
    s = s.replace(/\/+$/, '');
    // 3. Append /v1 if not already ending with /v1
    if (!/\/v1$/i.test(s)) {
      s = s + '/v1';
    }
    return s;
  }

  // ── Config ────────────────────────────────────────────────────────────────

  function getConfig() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const c = JSON.parse(raw);
        return {
          endpoint: c.endpoint || '',
          model:    c.model    || '',
          apiKey:   c.apiKey   || '',
          advanced: {
            temperature: c.advanced?.temperature ?? 0.4,
            maxTokens:   c.advanced?.maxTokens   ?? 1024,
          },
        };
      }
    } catch (e) {}
    return { endpoint: '', model: '', apiKey: '', advanced: { temperature: 0.4, maxTokens: 1024 } };
  }

  function saveConfig(endpoint, model, apiKey, advanced) {
    const adv = advanced || { temperature: 0.4, maxTokens: 1024 };
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ endpoint, model, apiKey, advanced: adv }));
  }

  function isConfigured() {
    const c = getConfig();
    return !!(c.endpoint && c.model);
  }

  // ── Local address detection ───────────────────────────────────────────────

  function isLocalAddress(url) {
    try {
      const host = new URL(url).hostname;
      // localhost and loopback
      if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return true;
      // IPv4 private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
      if (/^10\./.test(host)) return true;
      if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
      if (/^192\.168\./.test(host)) return true;
      // Link-local: 169.254.x.x
      if (/^169\.254\./.test(host)) return true;
      // .local mDNS hostnames
      if (/\.local$/.test(host)) return true;
      return false;
    } catch (e) {
      return false;
    }
  }

  // ── Connection test ───────────────────────────────────────────────────────

  async function testConnection(endpoint, apiKey) {
    const normalized = normalizeEndpoint(endpoint);
    if (!normalized) return { ok: false, error: 'no_endpoint', message: 'No endpoint provided.' };

    // Mixed-content detection: block HTTP from HTTPS page ONLY for non-local addresses.
    // Browsers allow HTTP requests to private/local IPs from HTTPS pages (mixed content
    // rules don't apply to RFC-1918 / loopback addresses in most browsers).
    if (window.location.protocol === 'https:' && normalized.startsWith('http://') && !isLocalAddress(normalized)) {
      return {
        ok: false,
        error: 'mixed_content',
        message: 'Browser blocks HTTP requests from HTTPS pages (public endpoints only). Use an HTTPS endpoint, or if your LM Studio is on a local/private IP, enter that address directly.',
      };
    }

    const headers = { 'Content-Type': 'application/json' };
    if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;

    const url = normalized + '/models';
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);

    try {
      const resp = await fetch(url, { headers, signal: controller.signal });
      clearTimeout(timer);
      if (!resp.ok) {
        return { ok: false, error: 'http_error', message: `HTTP ${resp.status}` };
      }
      const data = await resp.json();
      const models = Array.isArray(data.data)
        ? data.data.map(m => (typeof m === 'string' ? m : (m.id || String(m))))
        : [];
      return { ok: true, models };
    } catch (e) {
      clearTimeout(timer);
      if (e.name === 'AbortError') {
        return { ok: false, error: 'timeout', message: 'Connection timed out after 8s' };
      }
      return { ok: false, error: 'network', message: e.message };
    }
  }

  // ── Response text extraction ──────────────────────────────────────────────

  function extractText(value) {
    if (typeof value === 'string') return value;
    if (Array.isArray(value)) {
      return value.map(extractText).join('');
    }
    if (value && typeof value === 'object') {
      if (typeof value.text === 'string') return value.text;
      // For content: prefer non-empty, fallback to reasoning_content if content is empty
      const content = value.content || '';
      if (typeof content === 'string' && content.length > 0) return content;
      if (Array.isArray(value.content)) return value.content.map(extractText).join('');
      if (typeof value.output_text === 'string') return value.output_text;
      // Fallback to reasoning_content if content was empty
      if (typeof value.reasoning_content === 'string' && content === '') return value.reasoning_content;
      if (Array.isArray(value.parts)) return value.parts.map(extractText).join('');
      if (Array.isArray(value.items)) return value.items.map(extractText).join('');
    }
    return '';
  }

  // ── Streaming runner ──────────────────────────────────────────────────────

  async function runAI(messages, { signal, onChunk, onDone, onError } = {}) {
    const c = getConfig();
    if (!c.endpoint || !c.model) {
      if (onError) onError('AI not configured.');
      return;
    }
    const url = normalizeEndpoint(c.endpoint) + '/chat/completions';
    const headers = { 'Content-Type': 'application/json' };
    if (c.apiKey) headers['Authorization'] = `Bearer ${c.apiKey}`;

    // ── Attempt 1: streaming ────────────────────────────────────────────────
    let resp;
    try {
      resp = await fetch(url, {
        method: 'POST',
        headers,
        signal,
        body: JSON.stringify({
          model: c.model,
          messages,
          stream: true,
          temperature: c.advanced?.temperature ?? 0.4,
          max_tokens: c.advanced?.maxTokens ?? 1024,
        }),
      });
    } catch (e) {
      if (e.name === 'AbortError') return;
      // Network error → retry once with stream: false
      try {
        resp = await fetch(url, {
          method: 'POST',
          headers,
          signal,
          body: JSON.stringify({
            model: c.model,
            messages,
          stream: false,
          temperature: c.advanced?.temperature ?? 0.4,
          max_tokens: c.advanced?.maxTokens ?? 1024,
          }),
        });
        if (!resp.ok) {
          const text = await resp.text().catch(() => '');
          if (onError) onError(`HTTP ${resp.status}: ${text.slice(0, 120)}`);
          return;
        }
        const json = await resp.json();
        const choice = json.choices?.[0] || {};
        // extractText() already handles empty content → reasoning_content fallback
        const content = extractText(
          choice.message?.content
          || choice.text
          || choice.reasoning_content
          || json.output_text
          || ''
        );
        if (content && onChunk) onChunk(content);
        if (onDone) onDone();
        return;
      } catch (e2) {
        if (e2.name === 'AbortError') return;
        if (onError) onError(e2.message);
        return;
      }
    }

    if (!resp.ok) {
      const text = await resp.text().catch(() => '');
      if (onError) onError(`HTTP ${resp.status}: ${text.slice(0, 120)}`);
      return;
    }

    // ── Check Content-Type: if not SSE, treat as plain JSON completion ───────
    const ct = resp.headers.get('content-type') || '';
    if (!ct.includes('text/event-stream')) {
      try {
        const json = await resp.json();
        const choice = json.choices?.[0] || {};
        // extractText() already handles empty content → reasoning_content fallback
        const content = extractText(
          choice.message?.content
          || choice.text
          || choice.reasoning_content
          || json.output_text
          || ''
        );
        if (content && onChunk) onChunk(content);
        if (onDone) onDone();
      } catch (e) {
        if (onError) onError('Failed to parse JSON response: ' + e.message);
      }
      return;
    }

    // ── SSE streaming ────────────────────────────────────────────────────────
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let streamedText = '';

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        // SSE lines
        const lines = buf.split('\n');
        buf = lines.pop(); // keep incomplete line
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || !trimmed.startsWith('data:')) continue;
          const jsonStr = trimmed.slice(5).trim();
          if (jsonStr === '[DONE]') continue;
          try {
            const obj = JSON.parse(jsonStr);
            const choice = obj.choices?.[0] || {};
            // Some providers send true deltas, others send cumulative snapshots.
            // Normalize both to incremental chunks before forwarding to the UI.
            const piece = extractText(
              choice.delta?.content
              || choice.delta?.text
              || choice.message?.content
              || choice.message?.reasoning_content
              || choice.text
              || obj.output_text
              || ''
            );
            if (!piece || !onChunk) continue;

            let delta = piece;
            if (streamedText && piece.startsWith(streamedText)) {
              delta = piece.slice(streamedText.length);
              streamedText = piece;
            } else {
              streamedText += piece;
            }

            if (delta) onChunk(delta);
          } catch (_) {}
        }
      }
    } catch (e) {
      if (e.name === 'AbortError') return;
      if (onError) onError(e.message);
      return;
    }

    if (onDone) onDone();
  }

  // ── JSON extractor with smart bracket matching ──────────────────────────

  function parseJsonFromText(text) {
    if (!text) return null;
    const cleanedText = String(text)
      .replace(/<think>[\s\S]*?<\/think>/gi, '')
      .trim();
    
    // Try direct parse first
    try { return JSON.parse(cleanedText); } catch (_) {}
    
    // Extract from ```json ... ``` block
    const fence = cleanedText.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fence) {
      try { return JSON.parse(fence[1].trim()); } catch (_) {}
    }
    
    // Find first [ or { and extract properly matched JSON from there
    const arrIdx = cleanedText.indexOf('[');
    const objIdx = cleanedText.indexOf('{');
    let start = -1;
    if (arrIdx !== -1 && (objIdx === -1 || arrIdx < objIdx)) start = arrIdx;
    else if (objIdx !== -1) start = objIdx;
    
    if (start !== -1) {
      const opener = cleanedText[start];
      const closer = opener === '[' ? ']' : '}';
      
      // Scan forward from start, tracking bracket depth to find actual closing bracket
      let depth = 0;
      let end = -1;
      let inString = false;
      let escaped = false;
      
      for (let i = start; i < cleanedText.length; i++) {
        const ch = cleanedText[i];
        
        if (escaped) {
          escaped = false;
          continue;
        }
        
        if (ch === '\\') {
          escaped = true;
          continue;
        }
        
        if (ch === '"') {
          inString = !inString;
          continue;
        }
        
        if (!inString) {
          if (ch === opener) depth++;
          else if (ch === closer) {
            depth--;
            if (depth === 0) {
              end = i;
              break;
            }
          }
        }
      }
      
      // Try the properly matched JSON
      if (end > start) {
        try { return JSON.parse(cleanedText.slice(start, end + 1)); } catch (_) {}
      }
      
      // Fallback: try raw slice (might be truncated but valid prefix)
      try { return JSON.parse(cleanedText.slice(start)); } catch (_) {}
    }
    
    return null;
  }

  // ── Prompts ───────────────────────────────────────────────────────────────

  const PROMPTS = {
    title(yaml) {
      return [
        {
          role: 'system',
          content: 'You are a Sigma detection rule naming expert. Suggest 4 concise, specific rule titles. Follow conventions like "Suspicious X via Y", "Potential X Execution", or "X Abuse by Y". Return ONLY a JSON array of strings — no explanation, no markdown.',
        },
        {
          role: 'user',
          content: `Suggest 4 alternative titles for this Sigma rule. Return a JSON array of strings only:\n\n${yaml}`,
        },
      ];
    },

    describe(yaml) {
      return [
        {
          role: 'system',
          content: 'You are a cybersecurity expert specializing in SIEM detection engineering. Generate 3 alternative description paragraphs for a Sigma detection rule. Each should be 2–3 sentences, plain text, technical and specific. Return ONLY a JSON array of strings — no explanation, no markdown headers.',
        },
        {
          role: 'user',
          content: `Generate 3 description variants for this Sigma rule. Return a JSON array of strings only:\n\n${yaml}`,
        },
      ];
    },

    falsepositives(yaml) {
      return [
        {
          role: 'system',
          content: 'You are a cybersecurity expert specializing in SIEM detection engineering. Return ONLY a JSON array of strings — false positive scenarios for the given Sigma rule. No explanation, no markdown. Example: ["Legitimate admin tools", "IT automation scripts"]',
        },
        {
          role: 'user',
          content: `List likely false positives for this Sigma rule. Return a JSON array of strings only:\n\n${yaml}`,
        },
      ];
    },

    tags(yaml) {
      return [
        {
          role: 'system',
          content: 'You are a MITRE ATT&CK expert. Return ONLY a JSON array of MITRE ATT&CK technique IDs (e.g. ["T1059.001", "T1055"]) relevant to the given Sigma rule. No explanation, no markdown, no "attack." prefix — just the IDs.',
        },
        {
          role: 'user',
          content: `Suggest MITRE ATT&CK technique IDs for this Sigma rule. Return a JSON array of technique IDs only:\n\n${yaml}`,
        },
      ];
    },

    detection(yaml) {
      return [
        {
          role: 'system',
          content: `You are a senior Sigma detection engineer. Given a Sigma rule, suggest improvements or additions to the detection section. Return ONLY a JSON object with this structure:
{
  "groups": [
    {
      "name": "selection",
      "rationale": "why this group catches the behavior",
      "fields": [
        { "field": "FieldName", "modifier": "contains", "values": ["val1", "val2"], "note": "why this field/value" }
      ]
    }
  ],
  "filters": [
    {
      "name": "filter_legit",
      "rationale": "what this filters out",
      "fields": [
        { "field": "FieldName", "modifier": "", "values": ["legitimate_val"], "note": "context" }
      ]
    }
  ],
  "condition_suggestion": "selection and not filter_legit",
  "summary": "one sentence explaining the overall improvement"
}
Return ONLY valid JSON. filters array may be empty. Only suggest fields that exist in real Windows/Linux/network logs.`,
        },
        {
          role: 'user',
          content: `Suggest detection improvements for this Sigma rule. Return JSON only:\n\n${yaml}`,
        },
      ];
    },

    explain(yaml) {
      return [
        {
          role: 'system',
          content: 'You are a cybersecurity expert explaining SIEM detection rules to analysts. Use markdown formatting (bold, code, bullet lists). Be clear and educational.',
        },
        {
          role: 'user',
          content: `Explain this Sigma rule in detail — what it detects, why it matters, and how it works:\n\n${yaml}`,
        },
      ];
    },

    review(yaml) {
      return [
        {
          role: 'system',
          content: `You are a senior detection engineer reviewing Sigma rules. Return ONLY a JSON object with this exact structure:
{
  "summary": "one paragraph overall assessment",
  "score": 7,
  "annotations": [
    { "target": "exact text from the rule to highlight", "severity": "error|warning|info|good", "note": "brief explanation" }
  ]
}
Severity levels: error (must fix), warning (should fix), info (consider), good (well done).
Return ONLY valid JSON — no markdown, no extra text.`,
        },
        {
          role: 'user',
          content: `Review this Sigma rule and return the JSON assessment:\n\n${yaml}`,
        },
      ];
    },

    brainstorm(prompt) {
      return [
        {
          role: 'system',
          content: `You are helping a detection engineer bootstrap a Sigma rule draft from a rough idea. Return ONLY a valid JSON object with this structure:
{
  "scenario": "process|network|file|registry|auth|cloud|linux|blank",
  "title": "concise draft rule title",
  "description": "2-3 sentence draft description",
  "level": "informational|low|medium|high|critical",
  "logsource_id": "exact preset id if obvious, otherwise empty string",
  "falsepositives": ["fp1", "fp2"],
  "detection_stub": {
    "condition": "selection",
    "groups": [
      {
        "name": "selection",
        "type": "fields",
        "fields": [
          { "field": "FieldName", "modifier": "contains", "values": ["value1"] }
        ]
      }
    ]
  }
}
Keep it practical and conservative. If the idea is vague, make the safest reasonable draft. Return JSON only.`,
        },
        {
          role: 'user',
          content: `Bootstrap a Sigma starter rule from this idea:\n\n${prompt}`,
        },
      ];
    },
  };

  // ── Export ────────────────────────────────────────────────────────────────

  window.SigmaAI = {
    normalizeEndpoint,
    getConfig,
    saveConfig,
    isConfigured,
    testConnection,
    runAI,
    parseJsonFromText,
    PROMPTS,
  };
})();
