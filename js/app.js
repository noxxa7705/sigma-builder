// app.js — Sigma Rule Builder (Vue 3, static, no backend)
// Integrates SigmaHQ community rule browser via GitHub API
const { createApp, ref, computed, reactive, watch } = Vue;

// ── helpers ──────────────────────────────────────────────────────────────────

function uuid4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

function todayStr() {
  return new Date().toISOString().split('T')[0];
}

// ── YAML emitter ─────────────────────────────────────────────────────────────

function yamlStr(s) {
  if (s === null || s === undefined) return "''";
  const str = String(s);
  if (str === '') return "''";
  if (/[:#\[\]{},\|>&!*'"%@`?]/.test(str) || str.includes('\n') ||
      str.startsWith(' ') || str.endsWith(' ') ||
      str === 'true' || str === 'false' || str === 'null' ||
      /^\d/.test(str)) {
    return `'${str.replace(/'/g, "''")}'`;
  }
  return str;
}

function buildYaml(rule) {
  const lines = [];
  lines.push(`title: ${yamlStr(rule.title || '')}`);
  if (rule.id) lines.push(`id: ${rule.id}`);
  if (rule.related && rule.related.length) {
    lines.push('related:');
    rule.related.forEach(r => {
      lines.push(`  - id: ${yamlStr(r.id)}`);
      lines.push(`    type: ${yamlStr(r.type)}`);
    });
  }
  lines.push(`status: ${rule.status || 'experimental'}`);
  lines.push(`description: ${rule.description ? yamlStr(rule.description) : "''"}`);
  if (rule.references && rule.references.filter(Boolean).length) {
    lines.push('references:');
    rule.references.filter(Boolean).forEach(r => lines.push(`  - ${yamlStr(r)}`));
  }
  if (rule.author) lines.push(`author: ${yamlStr(rule.author)}`);
  lines.push(`date: ${rule.date || todayStr()}`);
  if (rule.modified) lines.push(`modified: ${rule.modified}`);
  if (rule.tags && rule.tags.length) {
    lines.push('tags:');
    rule.tags.forEach(t => lines.push(`  - ${t}`));
  }
  lines.push('logsource:');
  if (rule.logsource.category) lines.push(`  category: ${yamlStr(rule.logsource.category)}`);
  if (rule.logsource.product)  lines.push(`  product: ${yamlStr(rule.logsource.product)}`);
  if (rule.logsource.service)  lines.push(`  service: ${yamlStr(rule.logsource.service)}`);

  lines.push('detection:');
  rule.detection.groups.forEach(group => {
    const name = group.name || 'selection';
    // Add AI rationale as comment if present
    if (group._aiRationale) {
      lines.push(`  # ${group._aiRationale}`);
    }
    if (group.type === 'keywords') {
      lines.push(`  ${name}:`);
      group.keywords.filter(Boolean).forEach(kw => lines.push(`    - ${yamlStr(kw)}`));
    } else {
      const fieldLines = {};
      group.fields.forEach(f => {
        if (!f.field) return;
        const modKey = f.modifier ? `${f.field}|${f.modifier}` : f.field;
        if (!fieldLines[modKey]) fieldLines[modKey] = [];
        f.values.filter(Boolean).forEach(v => fieldLines[modKey].push(v));
      });
      if (Object.keys(fieldLines).length === 0) return;
      lines.push(`  ${name}:`);
      Object.entries(fieldLines).forEach(([key, vals]) => {
        if (vals.length === 1) {
          lines.push(`    ${key}: ${yamlStr(vals[0])}`);
        } else {
          lines.push(`    ${key}:`);
          vals.forEach(v => lines.push(`      - ${yamlStr(v)}`));
        }
      });
    }
  });
  lines.push(`  condition: ${rule.detection.condition || 'selection'}`);
  if (rule.detection.timeframe) lines.push(`  timeframe: ${rule.detection.timeframe}`);

  if (rule.fields && rule.fields.filter(Boolean).length) {
    lines.push('fields:');
    rule.fields.filter(Boolean).forEach(f => lines.push(`  - ${yamlStr(f)}`));
  }
  if (rule.falsepositives && rule.falsepositives.filter(Boolean).length) {
    lines.push('falsepositives:');
    rule.falsepositives.filter(Boolean).forEach(fp => lines.push(`  - ${yamlStr(fp)}`));
  } else {
    lines.push('falsepositives:');
    lines.push("  - Unknown");
  }
  lines.push(`level: ${rule.level || 'medium'}`);
  return lines.join('\n');
}

// ── YAML parser ───────────────────────────────────────────────────────────────

function parseYaml(text) {
  try {
    if (window.jsyaml) return window.jsyaml.load(text);
  } catch(e) {}
  return null;
}

function ruleFromParsed(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const rule = emptyRule();
  rule.title       = obj.title || '';
  rule.id          = obj.id || uuid4();
  rule.status      = obj.status || 'experimental';
  rule.description = obj.description || '';
  rule.author      = obj.author || '';
  rule.date        = obj.date ? String(obj.date) : todayStr();
  rule.modified    = obj.modified ? String(obj.modified) : '';
  rule.level       = obj.level || 'medium';
  rule.tags        = (obj.tags || []).filter(Boolean);
  rule.references  = Array.isArray(obj.references) ? obj.references.filter(Boolean) : [];
  rule.falsepositives = Array.isArray(obj.falsepositives) ? obj.falsepositives.filter(Boolean) : [''];
  rule.fields      = Array.isArray(obj.fields) ? obj.fields.filter(Boolean) : [];

  if (obj.logsource) {
    rule.logsource.category = obj.logsource.category || '';
    rule.logsource.product  = obj.logsource.product  || '';
    rule.logsource.service  = obj.logsource.service  || '';
  }
  if (obj.detection) {
    rule.detection.condition  = obj.detection.condition || 'selection';
    rule.detection.timeframe  = obj.detection.timeframe || '';

    // Internal app shape from shared URL hash / saved draft:
    // detection: { groups: [...], condition, timeframe }
    if (Array.isArray(obj.detection.groups)) {
      rule.detection.groups = obj.detection.groups.map((g, idx) => ({
        id: g.id || uuid4(),
        name: g.name || (idx === 0 ? 'selection' : `filter_${idx}`),
        type: g.type === 'keywords' ? 'keywords' : 'fields',
        _aiRationale: g._aiRationale || '', // Preserve AI rationale
        fields: Array.isArray(g.fields) && g.fields.length
          ? g.fields.map(f => ({
              id: f.id || uuid4(),
              field: String(f.field || ''),
              modifier: String(f.modifier || ''),
              values: Array.isArray(f.values) && f.values.length ? f.values.map(v => String(v ?? '')) : [''],
            }))
          : [emptyField()],
        keywords: Array.isArray(g.keywords) && g.keywords.length ? g.keywords.map(k => String(k ?? '')) : [''],
      }));
    } else {
      // Sigma/YAML shape:
      // detection: { selection: {...}, filter_x: {...}, condition, timeframe }
      rule.detection.groups = [];
      Object.entries(obj.detection).forEach(([key, val]) => {
        if (key === 'condition' || key === 'timeframe') return;
        const group = { id: uuid4(), name: key, type: 'fields', fields: [], keywords: [''] };
        if (Array.isArray(val) && val.every(v => typeof v === 'string')) {
          group.type = 'keywords';
          group.keywords = val;
        } else if (typeof val === 'object' && !Array.isArray(val) && val !== null) {
          group.type = 'fields';
          Object.entries(val).forEach(([fieldKey, fieldVal]) => {
            const parts = fieldKey.split('|');
            const field = parts[0];
            const modifier = parts.slice(1).join('|');
            const values = Array.isArray(fieldVal) ? fieldVal.map(String) : [String(fieldVal ?? '')];
            group.fields.push({ id: uuid4(), field, modifier, values });
          });
        }
        rule.detection.groups.push(group);
      });
    }

    if (rule.detection.groups.length === 0) rule.detection.groups.push(emptyGroup());
  }
  return rule;
}

// ── model factories ───────────────────────────────────────────────────────────

function emptyField()  { return { id: uuid4(), field: '', modifier: '', values: [''] }; }
function emptyGroup(name = 'selection') {
  return { id: uuid4(), name, type: 'fields', fields: [emptyField()], keywords: [''] };
}
function emptyRule() {
  return {
    title: '', id: uuid4(), status: 'experimental', description: '',
    author: '', date: todayStr(), modified: '', level: 'medium',
    tags: [], references: [''], falsepositives: [''], fields: [''],
    logsource: { category: '', product: '', service: '' },
    detection: { groups: [emptyGroup()], condition: 'selection', timeframe: '' },
    related: []
  };
}

function starterRule() {
  const rule = emptyRule();
  rule.title = 'Draft Sigma Rule';
  rule.logsource.category = 'process_creation';
  rule.logsource.product = 'windows';
  rule.detection.groups = [{
    id: uuid4(),
    name: 'selection',
    type: 'fields',
    fields: [{ id: uuid4(), field: 'Image', modifier: 'endswith', values: ['example.exe'] }],
    keywords: [''],
  }];
  rule.detection.condition = 'selection';
  rule.falsepositives = ['Legitimate administrative or automation activity'];
  return rule;
}

// ── linter ────────────────────────────────────────────────────────────────────

function lintRule(rule) {
  const errors = [], warnings = [];
  if (!rule.title.trim()) errors.push('Title is required.');
  if (!rule.description.trim()) warnings.push('Description is empty.');
  if (!rule.author.trim()) warnings.push('Author is not set.');
  if (!rule.logsource.product && !rule.logsource.service && !rule.logsource.category)
    errors.push('Logsource must have at least one of: product, service, or category.');
  if (!rule.detection.condition.trim()) errors.push('Detection condition is required.');
  const groupNames = rule.detection.groups.map(g => g.name);
  rule.detection.condition.split(/\s+/)
    .filter(w => !['and','or','not','1','of','all','them'].includes(w.toLowerCase()))
    .filter(w => !w.endsWith('*')).filter(w => w.trim())
    .forEach(w => {
      if (!groupNames.includes(w))
        warnings.push(`Condition references '${w}' which has no matching group.`);
    });
  rule.detection.groups.forEach(g => {
    if (g.type === 'fields') {
      if (!g.fields.some(f => f.field.trim() && f.values.some(v => v.trim())))
        errors.push(`Group '${g.name}' has no populated field-value pairs.`);
    } else {
      if (!g.keywords.some(k => k.trim()))
        errors.push(`Group '${g.name}' has no keywords.`);
    }
  });
  if (!rule.level) errors.push('Level is required.');
  if (!rule.status) errors.push('Status is required.');
  return { errors, warnings, valid: errors.length === 0 };
}

// ── GitHub API helpers ────────────────────────────────────────────────────────

const GH_API = 'https://api.github.com/repos/SigmaHQ/sigma/';
const GH_RAW = 'https://raw.githubusercontent.com/SigmaHQ/sigma/master/';

// Simple in-memory cache so we don't refetch the same category tree twice
const _treeCache = {};

async function fetchCategoryTree(path, githubToken) {
  if (_treeCache[path]) return _treeCache[path];
  const headers = { 'Accept': 'application/vnd.github.v3+json' };
  if (githubToken) headers['Authorization'] = `token ${githubToken}`;
  const url = `${GH_API}contents/${path}`;
  const resp = await fetch(url, { headers });
  if (!resp.ok) {
    if (resp.status === 403) throw new Error('GitHub rate limit hit — add a token in Settings or wait a bit.');
    if (resp.status === 404) throw new Error(`Path not found: ${path}`);
    throw new Error(`GitHub API error: ${resp.status}`);
  }
  const data = await resp.json();
  // Filter to .yml files only, map to { name, path, download_url }
  const files = data
    .filter(f => f.type === 'file' && f.name.endsWith('.yml'))
    .map(f => ({ name: f.name.replace(/\.yml$/, ''), path: f.path, download_url: f.download_url }));
  _treeCache[path] = files;
  return files;
}

async function fetchRuleRaw(path, githubToken) {
  const url = `${GH_RAW}${path}`;
  const headers = {};
  if (githubToken) headers['Authorization'] = `token ${githubToken}`;
  const resp = await fetch(url, { headers });
  if (!resp.ok) throw new Error(`Failed to fetch rule: ${resp.status}`);
  return resp.text();
}

// ── Shareable URL helpers ─────────────────────────────────────────────────────

function ruleToUrlHash(rule) {
  // Serialize the rule to minimal JSON, base64url-encode it
  // Use JSON.stringify on a clean plain object (not reactive proxy)
  const plain = JSON.parse(JSON.stringify(rule));
  const json = JSON.stringify(plain);
  // btoa doesn't handle unicode — use encodeURIComponent trick
  const b64 = btoa(unescape(encodeURIComponent(json)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return '#rule=' + b64;
}

function ruleFromUrlHash(hash) {
  // Returns parsed plain object or null
  try {
    const match = hash.match(/[#&]rule=([A-Za-z0-9_-]+)/);
    if (!match) return null;
    const b64 = match[1].replace(/-/g, '+').replace(/_/g, '/');
    const json = decodeURIComponent(escape(atob(b64)));
    return JSON.parse(json);
  } catch(e) { return null; }
}

// ── Local Rule Library ────────────────────────────────────────────────────────

const LIBRARY_KEY = 'sigma_rule_library';

function libraryLoad() {
  try { return JSON.parse(localStorage.getItem(LIBRARY_KEY) || '[]'); }
  catch(e) { return []; }
}

function librarySave(entries) {
  localStorage.setItem(LIBRARY_KEY, JSON.stringify(entries));
}

function libraryUpsert(ruleObj) {
  const entries = libraryLoad();
  const idx = entries.findIndex(e => e.id === ruleObj.id);
  const entry = {
    id: ruleObj.id,
    title: ruleObj.title || 'Untitled',
    level: ruleObj.level || 'medium',
    status: ruleObj.status || 'experimental',
    tags: ruleObj.tags || [],
    logsource: ruleObj.logsource || {},
    savedAt: new Date().toISOString(),
    rule: JSON.parse(JSON.stringify(ruleObj)),
  };
  if (idx >= 0) entries[idx] = entry;
  else entries.unshift(entry);
  librarySave(entries);
  return entries;
}

function libraryDelete(id) {
  const entries = libraryLoad().filter(e => e.id !== id);
  librarySave(entries);
  return entries;
}

// ── Vue app ───────────────────────────────────────────────────────────────────

createApp({
  setup() {
    const data = window.SIGMA_DATA;

    // ── core state ─────────────────────────────────────────────────────────
    const rule = reactive(starterRule());

    // ── Load from URL hash on startup ──────────────────────────────────────
    (function() {
      const obj = ruleFromUrlHash(window.location.hash);
      if (obj) {
        const loaded = ruleFromParsed(obj) || obj;
        Object.assign(rule, loaded);
        // Clean the hash without triggering a page reload
        history.replaceState(null, '', window.location.pathname + window.location.search);
        // notify will be called after notify is defined — defer it
        setTimeout(() => notify('Rule loaded from shared link'), 0);
      }
    })();

    // ── Watch rule changes — update URL hash live (throttled 600ms) ────────
    let _hashUpdateTimer = null;
    watch(
      () => JSON.stringify(rule),
      () => {
        clearTimeout(_hashUpdateTimer);
        _hashUpdateTimer = setTimeout(() => {
          history.replaceState(null, '', ruleToUrlHash(rule));
        }, 600);
      },
      { deep: true }
    );

    const activeTab = ref('metadata');
    const yamlOutput = computed(() => buildYaml(rule));
    const lint = computed(() => lintRule(rule));
    const selectedPreset = ref('');

    // logsource groups for <optgroup>
    const logsourceGroups = data.logsourceGroups;

    // field suggestions for current logsource preset
    const fieldSuggestions = computed(() => {
      const preset = data.logsources.find(l => l.id === selectedPreset.value);
      return preset ? preset.fields : [];
    });

    // ── tab status dots ────────────────────────────────────────────────────
    function tabStatus(tab) {
      if (tab === 'metadata') {
        if (!rule.title.trim()) return 'err';
        if (!rule.description.trim() || !rule.author.trim()) return 'warn';
        return 'ok';
      }
      if (tab === 'logsource') {
        if (!rule.logsource.product && !rule.logsource.service && !rule.logsource.category) return 'err';
        return 'ok';
      }
      if (tab === 'detection') {
        if (lint.value.errors.some(e => /condition|group|detection/i.test(e))) return 'err';
        return 'ok';
      }
      return '';
    }

    // ── notifications ──────────────────────────────────────────────────────
    const notification = ref('');
    let notifTimer = null;
    function notify(msg, duration = 3000) {
      notification.value = msg;
      clearTimeout(notifTimer);
      notifTimer = setTimeout(() => notification.value = '', duration);
    }

    // ── logsource preset ───────────────────────────────────────────────────
    function applyPreset(presetId) {
      const preset = data.logsources.find(l => l.id === presetId);
      if (!preset) return;
      rule.logsource.category = preset.category || '';
      rule.logsource.product  = preset.product  || '';
      rule.logsource.service  = preset.service  || '';
    }
    watch(selectedPreset, applyPreset);

    function syncPresetFromLogsource() {
      const match = data.logsources.find(l =>
        l.category === (rule.logsource.category || null) &&
        l.product   === (rule.logsource.product  || null) &&
        l.service   === (rule.logsource.service  || null)
      );
      selectedPreset.value = match ? match.id : '';
    }

    // ── detection helpers ──────────────────────────────────────────────────
    function addGroup() {
      const idx = rule.detection.groups.length + 1;
      rule.detection.groups.push(emptyGroup(`selection${idx > 1 ? idx : ''}`));
    }
    function removeGroup(id) {
      if (rule.detection.groups.length <= 1) return;
      rule.detection.groups.splice(rule.detection.groups.findIndex(g => g.id === id), 1);
    }
    function addField(group)              { group.fields.push(emptyField()); }
    function removeField(group, fieldId)  { if (group.fields.length > 1) group.fields.splice(group.fields.findIndex(f => f.id === fieldId), 1); }
    function addValue(field)              { field.values.push(''); }
    function removeValue(field, idx)      { if (field.values.length > 1) field.values.splice(idx, 1); }
    function addKeyword(group)            { group.keywords.push(''); }
    function removeKeyword(group, idx)    { if (group.keywords.length > 1) group.keywords.splice(idx, 1); }
    function setConditionTemplate(val)    { if (val !== '__custom__') rule.detection.condition = val; }

    // ── tags helpers ───────────────────────────────────────────────────────
    const tagSearch = ref('');
    const filteredMitre = computed(() => {
      const q = tagSearch.value.toLowerCase();
      return data.mitreTags.filter(t => t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q));
    });
    function toggleMitreTag(id) {
      const tag = `attack.${id.toLowerCase()}`;
      const idx = rule.tags.indexOf(tag);
      if (idx >= 0) rule.tags.splice(idx, 1);
      else rule.tags.push(tag);
    }
    function hasTag(id)       { return rule.tags.includes(`attack.${id.toLowerCase()}`); }
    function addCustomTag()   { rule.tags.push(''); }
    function removeTag(idx)   { rule.tags.splice(idx, 1); }

    // ── ATT&CK matrix state ────────────────────────────────────────────────
    const matrixSearch   = ref('');
    const matrixShowSubs = ref(false);
    const expandedTechs  = ref(new Set());

    function techMatchesSearch(tech) {
      const q = matrixSearch.value.toLowerCase();
      if (!q) return true;
      return tech.id.toLowerCase().includes(q) || tech.name.toLowerCase().includes(q);
    }
    function subMatchesSearch(sub) {
      const q = matrixSearch.value.toLowerCase();
      if (!q) return true;
      return sub.id.toLowerCase().includes(q) || sub.name.toLowerCase().includes(q);
    }
    function anySubMatches(tech) {
      if (!matrixSearch.value) return false;
      return tech.subs.some(s => subMatchesSearch(s));
    }

    // Build the tactic columns from window.ATTACK_MATRIX
    const matrixTactics = computed(() => {
      const M = window.ATTACK_MATRIX;
      if (!M) return [];
      const q = matrixSearch.value.toLowerCase();
      return M.tacticOrder.map(tacId => {
        const techs = M.tactics[tacId] || [];
        const filtered = q
          ? techs.filter(t => techMatchesSearch(t) || anySubMatches(t))
          : techs;
        return {
          id: tacId,
          label: M.tacticLabels[tacId],
          techniques: filtered,
          visibleCount: filtered.length,
        };
      });
    });

    // Set of currently selected technique IDs (derived from rule.tags)
    const selectedTechIds = computed(() => {
      const s = new Set();
      rule.tags.forEach(tag => {
        const m = tag.match(/^attack\.(t\d+(?:\.\d+)?)$/i);
        if (m) s.add(m[1].toUpperCase());
      });
      return s;
    });

    function isSelected(id)  { return selectedTechIds.value.has(id.toUpperCase()); }

    function toggleTechCell(tech) {
      const tag = `attack.${tech.id.toLowerCase()}`;
      const idx = rule.tags.indexOf(tag);
      if (idx >= 0) rule.tags.splice(idx, 1);
      else rule.tags.push(tag);
    }
    function toggleSubCell(sub) {
      const tag = `attack.${sub.id.toLowerCase()}`;
      const idx = rule.tags.indexOf(tag);
      if (idx >= 0) rule.tags.splice(idx, 1);
      else rule.tags.push(tag);
    }
    function toggleExpand(techId) {
      const s = new Set(expandedTechs.value);
      if (s.has(techId)) s.delete(techId);
      else s.add(techId);
      expandedTechs.value = s;
    }
    function clearAllTags() {
      // Remove only attack.tXXXX tags
      const keep = rule.tags.filter(t => !/^attack\.t\d+/i.test(t));
      rule.tags.splice(0, rule.tags.length, ...keep);
    }

    // ── list helpers ───────────────────────────────────────────────────────
    function addListItem(arr)        { arr.push(''); }
    function removeListItem(arr, idx){
      // Allow deletion if there are multiple items, or if removing this leaves at least one placeholder
      const willHaveEmpty = arr.some((item, i) => i !== idx && item.trim() === '');
      if (arr.length > 1 && (arr.length > 2 || willHaveEmpty)) {
        arr.splice(idx, 1);
      }
    }

    // ── GitHub token (localStorage, never sent anywhere else) ──────────────
    const githubToken = ref(localStorage.getItem('sigma_gh_token') || '');
    const showSettings = ref(false);
    function saveToken() {
      localStorage.setItem('sigma_gh_token', githubToken.value);
      showSettings.value = false;
      notify('✓ Token saved');
    }

    // ── community browser state ────────────────────────────────────────────
    const showBrowser = ref(false);
    const browserSearch = ref('');
    const activeCatId = ref('');
    const catFiles = ref([]);       // files for active category
    const catLoading = ref(false);
    const catError = ref('');
    const ruleLoading = ref(false);
    const ruleError = ref('');

    // Group community categories
    const communityGroups = computed(() => {
      const groups = {};
      data.communityCategories.forEach(c => {
        if (!groups[c.group]) groups[c.group] = [];
        groups[c.group].push(c);
      });
      return groups;
    });

    // Filter displayed files by search query
    const filteredFiles = computed(() => {
      const q = browserSearch.value.toLowerCase().trim();
      if (!q) return catFiles.value;
      return catFiles.value.filter(f => f.name.toLowerCase().includes(q));
    });

    async function selectCategory(cat) {
      if (activeCatId.value === cat.id && catFiles.value.length) return; // already loaded
      activeCatId.value = cat.id;
      catFiles.value = [];
      catError.value = '';
      catLoading.value = true;
      browserSearch.value = '';
      try {
        const files = await fetchCategoryTree(cat.path, githubToken.value);
        catFiles.value = files;
      } catch(e) {
        catError.value = e.message;
      } finally {
        catLoading.value = false;
      }
    }

    async function loadCommunityRule(file) {
      ruleError.value = '';
      ruleLoading.value = true;
      try {
        const text = await fetchRuleRaw(file.path, githubToken.value);
        const parsed = parseYaml(text);
        const loaded = ruleFromParsed(parsed);
        if (!loaded) throw new Error('Could not parse rule YAML');
        Object.assign(rule, loaded);
        syncPresetFromLogsource();
        showBrowser.value = false;
        activeTab.value = 'metadata';
        notify(`✓ Loaded: ${file.name}`);
      } catch(e) {
        ruleError.value = e.message;
      } finally {
        ruleLoading.value = false;
      }
    }

    // ── pinned / local templates ───────────────────────────────────────────
    const showTemplates = ref(false);
    const templateLoading = ref(false);
    const templateError = ref('');

    function templateUrl(file) {
      const base = window.location.href.replace(/\/[^/]*$/, '');
      return `${base}/${file}`;
    }

    async function loadPinnedTemplate(tpl) {
      templateLoading.value = true;
      templateError.value = '';
      try {
        const resp = await fetch(templateUrl(tpl.file));
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const text = await resp.text();
        const parsed = parseYaml(text);
        const loaded = ruleFromParsed(parsed);
        if (!loaded) throw new Error('Failed to parse template YAML');
        Object.assign(rule, loaded);
        syncPresetFromLogsource();
        showTemplates.value = false;
        activeTab.value = 'metadata';
        notify(`✓ Template loaded: ${tpl.label}`);
      } catch(e) {
        templateError.value = `Failed to load: ${e.message}`;
      } finally {
        templateLoading.value = false;
      }
    }

    // ── import ─────────────────────────────────────────────────────────────
    const importText  = ref('');
    const importError = ref('');
    const showImport  = ref(false);

    function doImport() {
      importError.value = '';
      const parsed = parseYaml(importText.value);
      const loaded = ruleFromParsed(parsed);
      if (!loaded) { importError.value = 'Could not parse YAML. Check rule syntax.'; return; }
      Object.assign(rule, loaded);
      syncPresetFromLogsource();
      showImport.value = false;
      importText.value = '';
      activeTab.value = 'metadata';
      notify('✓ Rule imported');
    }

    // ── export / copy ──────────────────────────────────────────────────────
    const copied = ref(false);

    function exportRule() {
      const blob = new Blob([buildYaml(rule)], { type: 'text/yaml' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      const slug = rule.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'sigma-rule';
      a.download = `${slug}.yml`;
      a.click();
      URL.revokeObjectURL(a.href);
      notify('✓ Exported');
    }

    async function copyYaml() {
      await navigator.clipboard.writeText(yamlOutput.value).catch(() => {});
      copied.value = true;
      setTimeout(() => copied.value = false, 2000);
      notify('✓ Copied to clipboard');
    }

    // ── share link ────────────────────────────────────────────────────────────
    function copyShareLink() {
      const url = window.location.origin + window.location.pathname + ruleToUrlHash(rule);
      navigator.clipboard.writeText(url).then(() => notify('Share link copied!'));
    }

    // ── new / reset ────────────────────────────────────────────────────────────
    function newRule() {
      if (!confirm('Start a new rule? Unsaved changes will be lost.')) return;
      Object.assign(rule, starterRule());
      selectedPreset.value = '';
      activeTab.value = 'metadata';
      notify('New rule started');
    }

    function regenId() { rule.id = uuid4(); }

    // ── Wizard ─────────────────────────────────────────────────────────────────

    const wizardScenarios = [
      { id: 'process',    icon: '🖥', label: 'Process Execution',  desc: 'suspicious process, LOLBaS, LOLBIN' },
      { id: 'network',    icon: '🌐', label: 'Network Activity',   desc: 'C2, DNS, suspicious connections' },
      { id: 'file',       icon: '📁', label: 'File System',        desc: 'suspicious file creation/modification' },
      { id: 'registry',   icon: '🗒', label: 'Registry Changes',   desc: 'persistence, run keys' },
      { id: 'auth',       icon: '🔑', label: 'Authentication',     desc: 'logon failures, brute force, suspicious auth' },
      { id: 'cloud',      icon: '☁', label: 'Cloud / Azure',      desc: 'Azure AD, O365, CloudTrail' },
      { id: 'linux',      icon: '🐧', label: 'Linux / Mac',        desc: 'bash, ssh, auditd' },
      { id: 'blank',      icon: '✎', label: 'Custom / Blank',     desc: 'start from scratch, no pre-fill' },
    ];

    // Scenario → logsource hints for filtering
    const scenarioLsHints = {
      process:  { category: 'process_creation' },
      network:  { category: 'network_connection' },
      file:     { category: 'file_event' },
      registry: { category: 'registry_event' },
      auth:     { product: 'windows', service: 'security' },
      cloud:    { product: 'azure' },
      linux:    { product: 'linux' },
      blank:    {},
    };

    // Scenario → default logsource values for new rule
    const scenarioDefaults = {
      process:  { category: 'process_creation', product: 'windows', service: '' },
      network:  { category: 'network_connection', product: '', service: '' },
      file:     { category: 'file_event', product: '', service: '' },
      registry: { category: 'registry_event', product: '', service: '' },
      auth:     { category: '', product: 'windows', service: 'security' },
      cloud:    { category: '', product: 'azure', service: '' },
      linux:    { category: '', product: 'linux', service: '' },
      blank:    { category: '', product: '', service: '' },
    };

    const wizard = reactive({
      open: false, step: 1,
      scenario: '', title: '', level: 'medium', author: '', description: '',
      logsourceId: '',
      aiDescLoading: false, aiDescText: '',
      aiLsLoading: false, aiLsText: '',
      brainstormPrompt: '',
      brainstormLoading: false,
      brainstormText: '',
      brainstormPlan: null,
    });

    const wizardFilteredLogsources = computed(() => {
      if (!wizard.scenario || wizard.scenario === 'blank') return data.logsources;
      const hint = scenarioLsHints[wizard.scenario] || {};
      return data.logsources.filter(ls => {
        if (hint.category && ls.category === hint.category) return true;
        if (hint.product && ls.product === hint.product) return true;
        if (hint.service && ls.service === hint.service) return true;
        return false;
      });
    });

    const wizardPreviewYaml = computed(() => {
      const r = _buildWizardRule();
      return buildYaml(r);
    });

    function _buildWizardRule() {
      const r = emptyRule();
      r.title = wizard.title || 'Untitled Rule';
      r.level = wizard.level || 'medium';
      r.author = wizard.author || '';
      r.description = wizard.description || '';

      const sc = wizard.scenario;
      const def = scenarioDefaults[sc] || {};

      // If user picked a logsource preset
      if (wizard.logsourceId) {
        const preset = data.logsources.find(l => l.id === wizard.logsourceId);
        if (preset) {
          r.logsource.category = preset.category || '';
          r.logsource.product  = preset.product  || '';
          r.logsource.service  = preset.service  || '';
        }
      } else {
        r.logsource.category = def.category || '';
        r.logsource.product  = def.product  || '';
        r.logsource.service  = def.service  || '';
      }

      // Set condition to 'selection' for scenarios that make sense
      if (sc !== 'blank') r.detection.condition = 'selection';

      if (wizard.brainstormPlan?.detection_stub?.groups?.length) {
        r.detection.groups = wizard.brainstormPlan.detection_stub.groups.map((group, idx) => ({
          id: uuid4(),
          name: group.name || (idx === 0 ? 'selection' : `group_${idx + 1}`),
          type: group.type === 'keywords' ? 'keywords' : 'fields',
          fields: Array.isArray(group.fields) && group.fields.length
            ? group.fields.map(f => ({
                id: uuid4(),
                field: f.field || '',
                modifier: f.modifier || '',
                values: Array.isArray(f.values) && f.values.length ? f.values.map(v => String(v)) : [''],
              }))
            : [emptyField()],
          keywords: Array.isArray(group.keywords) && group.keywords.length ? group.keywords.map(String) : [''],
        }));
      }

      if (wizard.brainstormPlan?.detection_stub?.condition) {
        r.detection.condition = wizard.brainstormPlan.detection_stub.condition;
      }

      if (Array.isArray(wizard.brainstormPlan?.falsepositives) && wizard.brainstormPlan.falsepositives.length) {
        r.falsepositives = wizard.brainstormPlan.falsepositives.filter(Boolean);
      }

      return r;
    }

    function openWizard() {
      wizard.open = true;
      wizard.step = 1;
      wizard.scenario = '';
      wizard.title = '';
      wizard.level = 'medium';
      wizard.author = localStorage.getItem('sigma_author') || '';
      wizard.description = '';
      wizard.logsourceId = '';
      wizard.aiDescText = '';
      wizard.aiLsText = '';
      wizard.brainstormPrompt = '';
      wizard.brainstormLoading = false;
      wizard.brainstormText = '';
      wizard.brainstormPlan = null;
    }

    function applyWizardBrainstorm(plan) {
      if (!plan || typeof plan !== 'object') return;
      const scenarios = new Set(wizardScenarios.map(sc => sc.id));
      if (plan.scenario && scenarios.has(plan.scenario)) wizard.scenario = plan.scenario;
      if (typeof plan.title === 'string' && plan.title.trim()) wizard.title = plan.title.trim();
      if (typeof plan.description === 'string' && plan.description.trim()) wizard.description = plan.description.trim();
      if (typeof plan.level === 'string' && ['informational', 'low', 'medium', 'high', 'critical'].includes(plan.level)) wizard.level = plan.level;
      if (typeof plan.logsource_id === 'string') {
        const found = data.logsources.find(ls => ls.id === plan.logsource_id.trim());
        if (found) wizard.logsourceId = found.id;
      }
      wizard.brainstormPlan = plan;
    }

    function wizardBrainstorm() {
      if (!AI.isConfigured()) { showSettings.value = true; notify('Configure an AI endpoint first'); return; }
      if (!wizard.brainstormPrompt.trim()) return;

      wizard.brainstormLoading = true;
      wizard.brainstormText = '';
      wizard.brainstormPlan = null;

      AI.runAI(AI.PROMPTS.brainstorm(wizard.brainstormPrompt.trim()), {
        onChunk(c) { wizard.brainstormText += c; },
        onDone() {
          wizard.brainstormLoading = false;
          // Clean brainstorm text before parsing (remove <think>, fences, etc.)
          const cleaned = cleanAiText(wizard.brainstormText);
          const parsed = AI.parseJsonFromText(cleaned);
          if (parsed && typeof parsed === 'object') {
            applyWizardBrainstorm(parsed);
            wizard.brainstormText = ''; // Clear raw text on success
          } else {
            // Show diagnostic: what we tried to parse
            console.error('Brainstorm parse failed. Cleaned text:', cleaned.slice(0, 200));
            wizard.brainstormText = `Could not parse brainstorm output.${cleaned ? ` (got: ${cleaned.slice(0, 80).replace(/\n/g, ' ')})` : ''}`;
          }
        },
        onError(e) {
          wizard.brainstormLoading = false;
          wizard.brainstormText = `Error: ${e}`;
        },
      });
    }

    function wizardNext() {
      if (wizard.step === 1 && !wizard.scenario) return;
      if (wizard.step === 2) {
        // Save author to localStorage
        if (wizard.author) localStorage.setItem('sigma_author', wizard.author);
        // Auto-select logsource based on scenario if none picked
        if (!wizard.logsourceId && wizard.scenario !== 'blank') {
          const filtered = wizardFilteredLogsources.value;
          if (filtered.length === 1) wizard.logsourceId = filtered[0].id;
        }
      }
      wizard.step++;
    }

    function wizardStart() {
      const r = _buildWizardRule();
      // Apply to reactive rule
      Object.assign(rule, r);
      syncPresetFromLogsource();
      wizard.open = false;
      activeTab.value = 'metadata';
      notify('✓ New rule created');
    }

    function wizardAiDescribe() {
      if (!AI.isConfigured()) return;
      wizard.aiDescLoading = true;
      wizard.aiDescText = '';
      const stub = `title: ${wizard.title || 'Untitled'}\nscenario: ${wizard.scenario}`;
      const messages = [
        { role: 'system', content: 'You are a cybersecurity expert. Write a concise 2-3 sentence description for a Sigma detection rule. Plain text only.' },
        { role: 'user', content: `Write a description for a Sigma rule with this context:\n${stub}` },
      ];
      AI.runAI(messages, {
        onChunk(c) { wizard.aiDescText += c; },
        onDone()   { wizard.aiDescLoading = false; },
        onError(e) { wizard.aiDescLoading = false; wizard.aiDescText = `Error: ${e}`; },
      });
    }

    function wizardAiLogsource() {
      if (!AI.isConfigured()) return;
      wizard.aiLsLoading = true;
      wizard.aiLsText = 'Thinking…';
      const lsNames = data.logsources.map(l => `${l.id}: ${l.label}`).join('\n');
      const messages = [
        { role: 'system', content: `You are a Sigma detection expert. Given a detection scenario, pick the best logsource preset ID from the list. Return ONLY the preset ID string, nothing else.\n\nAvailable presets:\n${lsNames}` },
        { role: 'user', content: `Scenario: ${wizard.scenario}\nTitle: ${wizard.title || 'unknown'}\nPick the best logsource preset ID:` },
      ];
      AI.runAI(messages, {
        onChunk(c) { wizard.aiLsText = (wizard.aiLsText === 'Thinking…' ? '' : wizard.aiLsText) + c; },
        onDone() {
          wizard.aiLsLoading = false;
          const suggested = extractSingleSuggestion(wizard.aiLsText)
            .replace(/[`"']/g, '')
            .trim();
          const found = data.logsources.find(l => l.id === suggested);
          if (found) {
            wizard.logsourceId = found.id;
            wizard.aiLsText = `✓ Suggested: ${found.label}`;
          } else {
            wizard.aiLsText = suggested ? `Could not match "${suggested}"` : 'Could not parse logsource suggestion.';
          }
        },
        onError(e) { wizard.aiLsLoading = false; wizard.aiLsText = `Error: ${e}`; },
      });
    }

    // ── Context menu ────────────────────────────────────────────────────────
    const ctxMenu = reactive({ visible: false, x: 0, y: 0, items: [] });

    function showCtxMenu(event, items) {
      event.preventDefault();
      event.stopPropagation();
      const menuW = 220, menuH = items.length * 32 + 16;
      ctxMenu.x = Math.max(4, Math.min(event.clientX, window.innerWidth  - menuW - 8));
      ctxMenu.y = Math.max(4, Math.min(event.clientY, window.innerHeight - menuH - 8));
      ctxMenu.items = items;
      ctxMenu.visible = true;
    }
    function hideCtxMenu() { ctxMenu.visible = false; }

    function ctxMatrixCell(event, tech, isSub) {
      const sel = isSelected(tech.id);
      const hasSubs = !isSub && tech.subs?.length > 0;
      const anySubsSel = hasSubs && tech.subs.some(s => isSelected(s.id));
      const sigmaTag = `attack.${tech.id.toLowerCase()}`;
      const items = [
        { label: sel ? '✗  Deselect' : '✓  Select', action: () => isSub ? toggleSubCell(tech) : toggleTechCell(tech) },
      ];
      if (hasSubs) {
        items.push({ label: `⊕  Select all sub-techniques (${tech.subs.length})`, action: () => { tech.subs.forEach(s => { const t=`attack.${s.id.toLowerCase()}`; if(!rule.tags.includes(t)) rule.tags.push(t); }); } });
        if (anySubsSel) items.push({ label: '⊖  Deselect all sub-techniques', action: () => { tech.subs.forEach(s => { const idx=rule.tags.indexOf(`attack.${s.id.toLowerCase()}`); if(idx>=0) rule.tags.splice(idx,1); }); } });
      }
      items.push({ separator: true });
      items.push({ label: `⎘  Copy T-ID  (${tech.id})`, action: () => navigator.clipboard.writeText(tech.id) });
      items.push({ label: `⎘  Copy Sigma tag  (${sigmaTag})`, action: () => navigator.clipboard.writeText(sigmaTag) });
      const selCount = selectedTechIds.value.size;
      items.push({ label: `⎘  Copy all selected tags${selCount ? ` (${selCount})` : ''}`, action: () => navigator.clipboard.writeText(rule.tags.filter(t=>/^attack\.t/i.test(t)).join('\n')), disabled: !selCount });
      items.push({ separator: true });
      items.push({ label: '↗  Open on MITRE ATT&CK', action: () => window.open(`https://attack.mitre.org/techniques/${tech.id.replace('.','/') }/`, '_blank') });
      showCtxMenu(event, items);
    }

    function ctxBrowserFile(event, file) {
      const rawUrl = `https://raw.githubusercontent.com/SigmaHQ/sigma/master/${file.path}`;
      const ghUrl  = `https://github.com/SigmaHQ/sigma/blob/master/${file.path}`;
      showCtxMenu(event, [
        { label: '→  Load into editor', action: () => loadCommunityRule(file) },
        { separator: true },
        { label: '↗  Open raw on GitHub',  action: () => window.open(rawUrl, '_blank') },
        { label: '↗  View on GitHub',      action: () => window.open(ghUrl,  '_blank') },
        { label: '⎘  Copy file path',      action: () => navigator.clipboard.writeText(file.path) },
      ]);
    }

    function ctxYamlPreview(event) {
      showCtxMenu(event, [
        { label: '⎘  Copy YAML',    action: () => copyYaml() },
        { label: '↓  Download .yml', action: () => exportRule() },
      ]);
    }

    // ── AI augmentation ────────────────────────────────────────────────────
    const AI = window.SigmaAI;

    const aiAvailable = computed(() => AI.isConfigured());

    // Per-feature state
    function mkAiState() {
      return reactive({ visible: false, loading: false, text: '', rawText: '', error: '',
                        suggestions: [], score: 0, summary: '', annotations: [] });
    }
    const aiState = reactive({
      title:          mkAiState(),
      describe:       mkAiState(),
      falsepositives: mkAiState(),
      tags:           mkAiState(),
      detection:      mkAiState(),
      explain:        mkAiState(),
      review:         mkAiState(),
    });

    function cleanAiText(raw) {
      return String(raw || '')
        .replace(/<think>[\s\S]*?<\/think>/gi, '')
        .replace(/^```[a-z]*\n?/i, '')
        .replace(/\n?```$/i, '')
        .trim();
    }

    function extractSuggestionList(raw, { mapper = (item) => item } = {}) {
      const normalize = (items) => items
        .map(item => typeof item === 'string' ? item : '')
        .map(item => mapper(item.trim()))
        .filter(item => item && item.length >= 3)  // At least 3 chars (filter out punctuation)
        .filter(item => !/^(?:\[|\{|\]|\}|```|json\b)/i.test(item))
        .filter(item => item.length < 500)
        .filter(item => !/^\s*[\[{].*[\]}]\s*$/.test(item));

      // 1) Try full JSON parse first
      const parsed = AI.parseJsonFromText(raw);
      if (Array.isArray(parsed)) {
        return [...new Set(normalize(parsed))];
      }
      if (parsed && typeof parsed === 'object') {
        const firstArray = Object.values(parsed).find(Array.isArray);
        if (Array.isArray(firstArray)) return [...new Set(normalize(firstArray))];
      }

      const cleaned = cleanAiText(raw);
      if (!cleaned) return [];

      // 2) If full JSON failed, salvage any valid JSON string literals already present.
      // This handles truncated arrays like:
      //   ["item 1", "item 2"
      // and ignores everything outside the quoted strings.
      const stringLiterals = [];
      const literalRegex = /"((?:\\.|[^"\\])*)"/g;
      let match;
      while ((match = literalRegex.exec(cleaned)) !== null) {
        try {
          stringLiterals.push(JSON.parse(`"${match[1]}"`));
        } catch (_) {}
      }
      if (stringLiterals.length) {
        return [...new Set(normalize(stringLiterals))];
      }

      // 3) Fall back to line parsing for non-JSON plain-text outputs.
      const lines = cleaned
        .split(/\r?\n+/)
        .map(line => line.replace(/^[-*•\d.)\s]+/, '').trim())
        .filter(Boolean)
        .filter(line => !/^```/.test(line))
        .filter(line => !/^json$/i.test(line));
      if (lines.length) {
        return [...new Set(normalize(lines))];
      }

      // 4) If it still looks like JSON but we could not recover valid string items, give up safely.
      if (cleaned.startsWith('[') || cleaned.startsWith('{')) {
        return [];
      }

      // 5) Single plain-text response.
      return [...new Set(normalize([cleaned]))];
    }

    function extractSingleSuggestion(raw) {
      const parsed = AI.parseJsonFromText(raw);
      if (typeof parsed === 'string') return parsed.trim();
      if (Array.isArray(parsed)) {
        const first = parsed.find(item => typeof item === 'string' && item.trim());
        if (first) return first.trim();
      }
      if (parsed && typeof parsed === 'object') {
        const firstString = Object.values(parsed).find(v => typeof v === 'string' && v.trim());
        if (typeof firstString === 'string') return firstString.trim();
      }

      return cleanAiText(raw)
        .split(/\r?\n+/)
        .map(line => line.replace(/^[-*•\d.)\s]+/, '').trim())
        .find(Boolean) || '';
    }

    function normalizeAttackTag(tag) {
      const cleaned = String(tag || '')
        .trim()
        .replace(/^attack\./i, '')
        .replace(/[`"'\s]/g, '')
        .toLowerCase();
      return cleaned ? `attack.${cleaned}` : '';
    }

    // AI settings
    const aiEndpoint = ref(AI.getConfig().endpoint);
    const aiModel    = ref(AI.getConfig().model);
    const aiApiKey   = ref(AI.getConfig().apiKey || '');
    const aiAvailableModels = ref([]);
    const aiLiveStatus = ref('idle');   // 'idle' | 'testing' | 'ok' | 'error' | 'mixed'
    const aiLiveError  = ref('');
    const aiShowAdvanced = ref(false);
    const aiAdvTemp      = ref(AI.getConfig().advanced?.temperature ?? 0.4);
    const aiAdvMaxTokens = ref(AI.getConfig().advanced?.maxTokens   ?? 1024);

    const aiLiveBadgeText = computed(() => {
      if (!aiEndpoint.value) return '';
      if (aiLiveStatus.value === 'testing') return '⟳';
      if (aiLiveStatus.value === 'ok')      return '✓ connected';
      if (aiLiveStatus.value === 'mixed')   return '⚠ HTTPS required';
      if (aiLiveStatus.value === 'error')   return '✗ ' + aiLiveError.value;
      return '○';
    });

    const aiLiveBadgeClass = computed(() => ({
      'badge-ok':      aiLiveStatus.value === 'ok',
      'badge-err':     aiLiveStatus.value === 'error',
      'badge-warn':    aiLiveStatus.value === 'mixed',
      'badge-testing': aiLiveStatus.value === 'testing',
      'badge-idle':    !aiEndpoint.value || aiLiveStatus.value === 'idle',
    }));

    // Use helpers from ai-panel-mixin.js
    function aiPanelHeading(feature) { return window.AiPanelHelpers.getAiPanelHeading(feature); }
    function aiLoadingLabel(feature) { return window.AiPanelHelpers.getAiLoadingLabel(feature); }

    const aiModelRecommendation = computed(() => {
      const m = aiModel.value || '';
      if (!m) return '';
      // Analyze model name to suggest quality for structured JSON
      const lower = m.toLowerCase();
      if (lower.includes('glm-4.6') || lower.includes('glm-4')) return '✓ Good for JSON (GLM)';
      if (lower.includes('gpt-5') || lower.includes('gpt-4o')) return '✓ Excellent for JSON (GPT)';
      if (lower.includes('mistral') && !lower.includes('small')) return '✓ Good for JSON (Mistral)';
      if (lower.includes('qwen') && lower.includes('3.5-9b')) {
        if (lower.includes('aggressive')) return '⚠ May have reasoning — reduce max_tokens';
        return '⚠ May prioritize reasoning over JSON';
      }
      if (lower.includes('qwen')) return '⚠ May have reasoning — check model docs';
      return '';
    });

    function saveAiConfig() {
      AI.saveConfig(
        aiEndpoint.value,
        aiModel.value,
        aiApiKey.value,
        { temperature: aiAdvTemp.value, maxTokens: aiAdvMaxTokens.value }
      );
    }

    function onAiSettingChange() {
      saveAiConfig();
    }

    let _endpointDebounce = null;
    let _lastTestedEndpoint = null;
    function onEndpointInput() {
      // Clear models if endpoint changed (even before testing)
      if (_lastTestedEndpoint && _lastTestedEndpoint !== aiEndpoint.value) {
        aiAvailableModels.value = [];
      }
      aiLiveStatus.value = 'idle';
      aiLiveError.value = '';
      saveAiConfig();
      clearTimeout(_endpointDebounce);
      if (!aiEndpoint.value) return;
      aiLiveStatus.value = 'testing';
      _endpointDebounce = setTimeout(() => doLiveTest(), 1200);
    }

    async function doLiveTest() {
      if (!aiEndpoint.value) return;
      aiLiveStatus.value = 'testing';
      const result = await AI.testConnection(aiEndpoint.value, aiApiKey.value);
      _lastTestedEndpoint = aiEndpoint.value;  // Track what we just tested
      if (result.ok) {
        aiLiveStatus.value = 'ok';
        aiAvailableModels.value = result.models || [];
        if (!aiModel.value && aiAvailableModels.value.length) {
          aiModel.value = aiAvailableModels.value[0];
          saveAiConfig();
        }
      } else if (result.error === 'mixed_content') {
        aiLiveStatus.value = 'mixed';
        aiLiveError.value = '';
      } else {
        aiLiveStatus.value = 'error';
        aiLiveError.value = result.message || 'connection failed';
      }
    }

    async function refreshModels() {
      await doLiveTest();
    }

    // Watch for settings modal open — auto-detect endpoint
    watch(() => showSettings.value, (isOpen) => {
      if (isOpen && aiEndpoint.value && AI.isConfigured()) {
        // Settings opened and we have a configured endpoint — test connection
        if (aiLiveStatus.value === 'idle' || aiLiveStatus.value === 'error') {
          doLiveTest();
        }
      }
    });

    function aiDismiss(feature) {
      const s = aiState[feature];
      s.visible = false; s.loading = false; s.text = ''; s.rawText = '';
      s.error = ''; s.suggestions = []; s.score = 0; s.summary = ''; s.annotations = [];
      s._retryCount = 0; // Reset retry counter when dismissed
      if (s._abort) { s._abort.abort(); s._abort = null; }
    }

    function aiGenerate(feature) {
      if (!AI.isConfigured()) { showSettings.value = true; notify('Configure an AI endpoint first'); return; }
      const s = aiState[feature];
      if (s.loading) return;
      aiDismiss(feature);
      s.visible = true;
      s.loading = true;

      // Track retry count for list-based features
      s._retryCount = (s._retryCount || 0) + 1;
      const isListFeature = ['title', 'describe', 'falsepositives', 'tags'].includes(feature);
      const maxRetries = 3;

      const yaml = yamlOutput.value;
      const messages = AI.PROMPTS[feature](yaml);
      const ctrl = new AbortController();
      s._abort = ctrl;

      // Disable streaming for list-based features to ensure atomic JSON responses
      const streamMode = !isListFeature; // false for list features, true for others

      AI.runAI(messages, {
        signal: ctrl.signal,
        stream: streamMode,
        onChunk(chunk) {
          s.rawText += chunk;
          // For streaming display — show raw text while loading
          if (feature === 'describe') {
            s.text = s.rawText;
          } else if (feature === 'explain') {
            s.text = s.rawText;
          } else {
            s.text = s.rawText;
          }
        },
        onDone() {
          s.loading = false;
          const raw = s.rawText;
          if (feature === 'title') {
            s.suggestions = extractSuggestionList(raw);
            if (!s.suggestions.length) {
              if (s._retryCount < maxRetries) {
                s.loading = true;
                s.rawText = '';
                s.text = '';
                aiGenerate(feature);
              } else {
                s.error = `Could not parse title suggestions after ${maxRetries} attempts.`;
              }
            } else {
              s._retryCount = 0; // Reset on success
            }
          } else if (feature === 'describe') {
            s.suggestions = extractSuggestionList(raw);
            if (!s.suggestions.length) {
              if (s._retryCount < maxRetries) {
                s.loading = true;
                s.rawText = '';
                s.text = '';
                aiGenerate(feature);
              } else {
                s.error = `Could not parse description suggestions after ${maxRetries} attempts.`;
              }
            } else {
              s._retryCount = 0; // Reset on success
            }
          } else if (feature === 'tags') {
            s.suggestions = extractSuggestionList(raw, { mapper: normalizeAttackTag });
            if (!s.suggestions.length) {
              if (s._retryCount < maxRetries) {
                s.loading = true;
                s.rawText = '';
                s.text = '';
                aiGenerate(feature);
              } else {
                s.error = `Could not parse tag suggestions after ${maxRetries} attempts.`;
              }
            } else {
              s._retryCount = 0; // Reset on success
            }
          } else if (feature === 'falsepositives') {
            s.suggestions = extractSuggestionList(raw);
            if (!s.suggestions.length) {
              if (s._retryCount < maxRetries) {
                s.loading = true;
                s.rawText = '';
                s.text = '';
                aiGenerate(feature);
              } else {
                s.error = `Could not parse false positive suggestions after ${maxRetries} attempts.`;
              }
            } else {
              s._retryCount = 0; // Reset on success
            }
          } else if (feature === 'detection') {
            const parsed = AI.parseJsonFromText(raw);
            if (parsed && (parsed.groups || parsed.filters)) {
              s.suggestions = [parsed]; // store parsed object in suggestions[0]
              s.summary = parsed.summary || '';
              s._retryCount = 0; // Reset on success
            } else {
              if (s._retryCount < maxRetries) {
                s.loading = true;
                s.rawText = '';
                s.text = '';
                aiGenerate(feature);
              } else {
                s.error = `Could not parse detection suggestions after ${maxRetries} attempts.`;
              }
            }
          } else if (feature === 'review') {
            const parsed = AI.parseJsonFromText(raw);
            if (parsed && parsed.summary) {
              s.summary     = parsed.summary || '';
              s.score       = parsed.score   || 0;
              s.annotations = Array.isArray(parsed.annotations) ? parsed.annotations : [];
              s.text        = cleanAiText(raw);
              s._retryCount = 0; // Reset on success
            } else {
              if (s._retryCount < maxRetries) {
                s.loading = true;
                s.rawText = '';
                s.text = '';
                aiGenerate(feature);
              } else {
                s.error = `Could not parse review after ${maxRetries} attempts.`;
              }
            }
          } else if (feature === 'explain') {
            s.text = cleanAiText(raw);
          }
        },
        onError(err) {
          s.loading = false;
          s.error = err;
        },
      });
    }

    // Accept helpers
    function acceptAiSuggestion(feature) {
      if (feature === 'describe') {
        rule.description = aiState.describe.text.trim();
        aiDismiss('describe');
        notify('✓ Description updated');
      }
    }

    function acceptTitle(title) {
      rule.title = title;
      notify('✓ Title updated');
    }

    function acceptDescription(desc) {
      rule.description = desc;
      notify('✓ Description updated');
    }

    // Apply a single AI-suggested detection group or filter to the rule
    function acceptDetectionGroup(group, isFilter, suggestionIndex = -1) {
      const gName = group.name || (isFilter ? 'filter' : 'selection');
      // Check if a group with this name already exists
      const existing = rule.detection.groups.find(g => g.name === gName);
      if (existing) {
        // Merge fields in
        group.fields.forEach(f => {
          existing.fields.push({ id: uuid4(), field: f.field, modifier: f.modifier || '', values: f.values || [''] });
        });
        // Preserve rationale if not already set
        if (group.rationale && !existing._aiRationale) {
          existing._aiRationale = group.rationale;
        }
        notify(`✓ Merged into group \"${gName}\"`);
      } else {
        // Add as new group
        rule.detection.groups.push({
          id: uuid4(),
          name: gName,
          type: 'fields',
          keywords: [''],
          fields: group.fields.map(f => ({
            id: uuid4(), field: f.field, modifier: f.modifier || '', values: f.values || ['']
          })),
          _aiRationale: group.rationale || '', // Store AI rationale as comment
        });
        notify(`✓ Added group \"${gName}\"`);
      }

      // Remove from AI suggestions if clicked from suggestion panel
      if (suggestionIndex >= 0) {
        if (isFilter) {
          aiState.detection.suggestions[0].filters.splice(suggestionIndex, 1);
        } else {
          aiState.detection.suggestions[0].groups.splice(suggestionIndex, 1);
        }
        // If no more suggestions left, dismiss the panel
        if (!aiState.detection.suggestions[0].groups?.length && !aiState.detection.suggestions[0].filters?.length) {
          aiDismiss('detection');
        }
      }
    }

    function acceptDetectionCondition(cond) {
      rule.detection.condition = cond;
      notify('✓ Condition updated');
    }

    function acceptAllDetection() {
      const d = aiState.detection.suggestions[0];
      if (!d) return;
      (d.groups || []).forEach(g => acceptDetectionGroup(g, false));
      (d.filters || []).forEach(f => acceptDetectionGroup(f, true));
      if (d.condition_suggestion) acceptDetectionCondition(d.condition_suggestion);
      aiDismiss('detection');
      notify('✓ Detection suggestions applied');
    }

    function hasAiTag(tag) { return rule.tags.includes(tag); }
    function acceptAiTag(tag) {
      if (!rule.tags.includes(tag)) rule.tags.push(tag);
      else rule.tags.splice(rule.tags.indexOf(tag), 1);
    }
    function acceptAllAiTags() {
      aiState.tags.suggestions.forEach(t => { if (!rule.tags.includes(t)) rule.tags.push(t); });
      aiDismiss('tags');
      notify(`✓ Tags added`);
    }
    function acceptFP(fp, suggestionIndex = -1) {
      const empties = rule.falsepositives.findIndex(f => !f.trim());
      if (empties >= 0) rule.falsepositives[empties] = fp;
      else if (!rule.falsepositives.includes(fp)) rule.falsepositives.push(fp);

      if (suggestionIndex >= 0) {
        aiState.falsepositives.suggestions.splice(suggestionIndex, 1);
        if (!aiState.falsepositives.suggestions.length) {
          aiDismiss('falsepositives');
        }
      }
    }
    function acceptAllFPs() {
      aiState.falsepositives.suggestions.forEach(fp => acceptFP(fp));
      aiDismiss('falsepositives');
      notify('✓ False positives added');
    }

    function scoreClass(score) {
      if (score >= 8) return 'score-good';
      if (score >= 5) return 'score-ok';
      return 'score-low';
    }

    // Annotated YAML segments — splits yaml by annotation targets
    const annotatedYamlSegments = computed(() => {
      const yaml = yamlOutput.value;
      const annotations = aiState.review.annotations;
      if (!annotations.length) return [{ text: yaml }];
      // Build list of {start, end, severity, note} for each annotation target found in yaml
      const hits = [];
      annotations.forEach(a => {
        if (!a.target) return;
        let idx = 0;
        while (true) {
          const pos = yaml.indexOf(a.target, idx);
          if (pos === -1) break;
          hits.push({ start: pos, end: pos + a.target.length, severity: a.severity, note: a.note });
          idx = pos + 1;
        }
      });
      if (!hits.length) return [{ text: yaml }];
      // Sort by start position
      hits.sort((a, b) => a.start - b.start);
      // Merge overlapping
      const merged = [hits[0]];
      for (let i = 1; i < hits.length; i++) {
        const last = merged[merged.length - 1];
        if (hits[i].start < last.end) {
          last.end = Math.max(last.end, hits[i].end);
        } else {
          merged.push(hits[i]);
        }
      }
      // Build segments
      const segs = [];
      let cursor = 0;
      merged.forEach(h => {
        if (h.start > cursor) segs.push({ text: yaml.slice(cursor, h.start) });
        segs.push({ text: yaml.slice(h.start, h.end), severity: h.severity, note: h.note });
        cursor = h.end;
      });
      if (cursor < yaml.length) segs.push({ text: yaml.slice(cursor) });
      return segs;
    });

    // ── Rule Library ───────────────────────────────────────────────────────────
    const showLibrary     = ref(false);
    const libraryEntries  = ref(libraryLoad());
    const librarySearch   = ref('');

    const libraryFiltered = computed(() => {
      const q = librarySearch.value.toLowerCase();
      if (!q) return libraryEntries.value;
      return libraryEntries.value.filter(e =>
        e.title.toLowerCase().includes(q) ||
        (e.logsource?.product || '').toLowerCase().includes(q) ||
        e.tags.some(t => t.toLowerCase().includes(q))
      );
    });

    function applyParsedRule(ruleReactive, obj) {
      const loaded = ruleFromParsed(obj);
      if (!loaded) return;
      Object.assign(ruleReactive, loaded);
      syncPresetFromLogsource();
      activeTab.value = 'metadata';
    }

    function libSave() {
      libraryEntries.value = libraryUpsert(JSON.parse(JSON.stringify(rule)));
      notify('Rule saved to library');
    }

    function libLoad(entry) {
      applyParsedRule(rule, entry.rule);
      showLibrary.value = false;
      notify(`Loaded: ${entry.title}`);
    }

    function libDuplicate(entry) {
      const copy = JSON.parse(JSON.stringify(entry.rule));
      copy.id = uuid4();
      copy.title = copy.title + ' (copy)';
      copy.date = todayStr();
      libraryEntries.value = libraryUpsert(copy);
      notify('Duplicated — loading copy');
      applyParsedRule(rule, copy);
      showLibrary.value = false;
    }

    function libDelete(id) {
      if (!confirm('Delete this rule from the library?')) return;
      libraryEntries.value = libraryDelete(id);
      notify('Deleted from library');
    }

    function levelColor(level) {
      const map = { informational: '#60a5fa', low: '#4ade80', medium: '#facc15', high: '#fb923c', critical: '#f87171' };
      return map[level] || '#555';
    }

    function formatRelativeTime(iso) {
      const ms = Date.now() - new Date(iso).getTime();
      const min = Math.floor(ms / 60000);
      if (min < 1) return 'just now';
      if (min < 60) return `${min}m ago`;
      const h = Math.floor(min / 60);
      if (h < 24) return `${h}h ago`;
      const d = Math.floor(h / 24);
      return `${d}d ago`;
    }

    // Auto-save watcher — only updates entries already in the library
    let _libAutoSaveTimer = null;
    watch(
      () => JSON.stringify(rule),
      () => {
        clearTimeout(_libAutoSaveTimer);
        _libAutoSaveTimer = setTimeout(() => {
          const exists = libraryEntries.value.some(e => e.id === rule.id);
          if (exists) libraryEntries.value = libraryUpsert(JSON.parse(JSON.stringify(rule)));
        }, 1500);
      },
      { deep: true }
    );

    // ── Query Converter ──────────────────────────────────────────────────────

    const converterTarget = ref('spl');

    const converterResult = computed(() => {
      if (typeof SigmaConverter === 'undefined') return null;
      try { return SigmaConverter.convert(JSON.parse(JSON.stringify(rule))); }
      catch(e) { return null; }
    });

    const converterOutput = computed(() => {
      if (!converterResult.value) return '// Converter unavailable';
      return converterResult.value[converterTarget.value]?.query || '// No output';
    });

    const converterNote = computed(() => {
      if (!converterResult.value) return '';
      return converterResult.value[converterTarget.value]?.note || '';
    });

    function copyConverterOutput() {
      navigator.clipboard.writeText(converterOutput.value)
        .then(() => notify('Query copied!'));
    }

    // Simple markdown renderer (bold, italic, code, line breaks — no full parser needed)
    function renderMarkdown(text) {
      if (!text) return '';
      return text
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/^### (.+)$/gm, '<h4>$1</h4>')
        .replace(/^## (.+)$/gm, '<h3>$1</h3>')
        .replace(/^# (.+)$/gm, '<h3>$1</h3>')
        .replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
        .replace(/^[-*] (.+)$/gm, '<li>$1</li>')
        .replace(/\n\n/g, '</p><p>')
        .replace(/\n/g, '<br>');
    }

    return {
      data, rule, activeTab, yamlOutput, lint,
      selectedPreset, logsourceGroups, fieldSuggestions,
      tabStatus, notification,
      applyPreset,
      addGroup, removeGroup, addField, removeField,
      addValue, removeValue, addKeyword, removeKeyword, setConditionTemplate,
      tagSearch, filteredMitre, toggleMitreTag, hasTag, addCustomTag, removeTag,
      matrixSearch, matrixShowSubs, expandedTechs, matrixTactics, selectedTechIds,
      isSelected, techMatchesSearch, subMatchesSearch, anySubMatches,
      toggleTechCell, toggleSubCell, toggleExpand, clearAllTags,
      addListItem, removeListItem,
      githubToken, showSettings, saveToken,
      showBrowser, browserSearch, activeCatId,
      catFiles, catLoading, catError, ruleLoading, ruleError,
      communityGroups, filteredFiles,
      selectCategory, loadCommunityRule,
      showTemplates, templateLoading, templateError, loadPinnedTemplate,
      showImport, importText, importError, doImport,
      copied, exportRule, copyYaml, copyShareLink,
      newRule, regenId, openWizard,
      wizard, wizardScenarios, wizardFilteredLogsources, wizardPreviewYaml,
      wizardNext, wizardStart, wizardAiDescribe, wizardAiLogsource, wizardBrainstorm, applyWizardBrainstorm,
      ctxMenu, hideCtxMenu, ctxMatrixCell, ctxBrowserFile, ctxYamlPreview,
      aiAvailable, aiState,
      aiEndpoint, aiModel, aiApiKey,
      aiAvailableModels, aiLiveStatus, aiLiveError,
      aiLiveBadgeText, aiLiveBadgeClass, aiModelRecommendation,
      aiPanelHeading, aiLoadingLabel,
      aiShowAdvanced, aiAdvTemp, aiAdvMaxTokens,
      onEndpointInput, onAiSettingChange, refreshModels, saveAiConfig,
      aiGenerate, aiDismiss, acceptAiSuggestion,
      acceptTitle, acceptDescription,
      acceptDetectionGroup, acceptDetectionCondition, acceptAllDetection,
      hasAiTag, acceptAiTag, acceptAllAiTags,
      acceptFP, acceptAllFPs, scoreClass,
      annotatedYamlSegments, renderMarkdown,
      showLibrary, libraryEntries, librarySearch, libraryFiltered,
      libSave, libLoad, libDuplicate, libDelete,
      levelColor, formatRelativeTime,
      converterTarget, converterOutput, converterNote, copyConverterOutput,
    };
  }
}).mount('#app');
