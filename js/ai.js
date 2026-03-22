// ai.js — SigmaAI helper for the Sigma Rule Builder
// Exposes window.SigmaAI with config, prompts, streaming runner, and utilities.

(function () {
  'use strict';

  const STORAGE_KEY = 'sigma_ai_config';

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
        };
      }
    } catch (e) {}
    return { endpoint: '', model: '', apiKey: '' };
  }

  function saveConfig(endpoint, model, apiKey) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ endpoint, model, apiKey }));
  }

  function isConfigured() {
    const c = getConfig();
    return !!(c.endpoint && c.model);
  }

  // ── Connection test ───────────────────────────────────────────────────────

  async function testConnection() {
    const c = getConfig();
    if (!c.endpoint) throw new Error('No endpoint configured.');
    const headers = { 'Content-Type': 'application/json' };
    if (c.apiKey) headers['Authorization'] = `Bearer ${c.apiKey}`;
    // Try /models endpoint first (OpenAI-compatible)
    const url = c.endpoint.replace(/\/+$/, '') + '/models';
    const resp = await fetch(url, { headers });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const models = Array.isArray(data.data)
      ? data.data.map(m => m.id || m)
      : [];
    return { models };
  }

  // ── Streaming runner ──────────────────────────────────────────────────────

  async function runAI(messages, { signal, onChunk, onDone, onError } = {}) {
    const c = getConfig();
    if (!c.endpoint || !c.model) {
      if (onError) onError('AI not configured.');
      return;
    }
    const url = c.endpoint.replace(/\/+$/, '') + '/chat/completions';
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
          temperature: 0.4,
          max_tokens: 1024,
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
            temperature: 0.4,
            max_tokens: 1024,
          }),
        });
        if (!resp.ok) {
          const text = await resp.text().catch(() => '');
          if (onError) onError(`HTTP ${resp.status}: ${text.slice(0, 120)}`);
          return;
        }
        const json = await resp.json();
        const content = json.choices?.[0]?.message?.content || '';
        if (onChunk) onChunk(content);
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
        const content = json.choices?.[0]?.message?.content || '';
        if (onChunk) onChunk(content);
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
            const delta = obj.choices?.[0]?.delta?.content;
            if (delta && onChunk) onChunk(delta);
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

  // ── JSON extractor ────────────────────────────────────────────────────────

  function parseJsonFromText(text) {
    if (!text) return null;
    // Try direct parse first
    try { return JSON.parse(text.trim()); } catch (_) {}
    // Extract from ```json ... ``` block
    const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fence) {
      try { return JSON.parse(fence[1].trim()); } catch (_) {}
    }
    // Find first [ or { and try from there
    const arrIdx = text.indexOf('[');
    const objIdx = text.indexOf('{');
    let start = -1;
    if (arrIdx !== -1 && (objIdx === -1 || arrIdx < objIdx)) start = arrIdx;
    else if (objIdx !== -1) start = objIdx;
    if (start !== -1) {
      try { return JSON.parse(text.slice(start)); } catch (_) {}
      // Try to find matching end bracket
      const opener = text[start];
      const closer = opener === '[' ? ']' : '}';
      const end = text.lastIndexOf(closer);
      if (end > start) {
        try { return JSON.parse(text.slice(start, end + 1)); } catch (_) {}
      }
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
  };

  // ── Export ────────────────────────────────────────────────────────────────

  window.SigmaAI = {
    getConfig,
    saveConfig,
    isConfigured,
    testConnection,
    runAI,
    parseJsonFromText,
    PROMPTS,
  };
})();
