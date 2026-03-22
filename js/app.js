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
  rule.falsepositives = Array.isArray(obj.falsepositives) ? obj.falsepositives.filter(Boolean) : ['Unknown'];
  rule.fields      = Array.isArray(obj.fields) ? obj.fields.filter(Boolean) : [];

  if (obj.logsource) {
    rule.logsource.category = obj.logsource.category || '';
    rule.logsource.product  = obj.logsource.product  || '';
    rule.logsource.service  = obj.logsource.service  || '';
  }
  if (obj.detection) {
    rule.detection.condition  = obj.detection.condition || 'selection';
    rule.detection.timeframe  = obj.detection.timeframe || '';
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
    tags: [], references: [''], falsepositives: ['Unknown'], fields: [''],
    logsource: { category: '', product: '', service: '' },
    detection: { groups: [emptyGroup()], condition: 'selection', timeframe: '' },
    related: []
  };
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

// ── Vue app ───────────────────────────────────────────────────────────────────

createApp({
  setup() {
    const data = window.SIGMA_DATA;

    // ── core state ─────────────────────────────────────────────────────────
    const rule = reactive(emptyRule());
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
    function removeListItem(arr, idx){ if (arr.length > 1) arr.splice(idx, 1); }

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

    // ── new / reset ────────────────────────────────────────────────────────
    function newRule() {
      if (!confirm('Start a new rule? Unsaved changes will be lost.')) return;
      Object.assign(rule, emptyRule());
      selectedPreset.value = '';
      activeTab.value = 'metadata';
      notify('New rule started');
    }

    function regenId() { rule.id = uuid4(); }

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
      copied, exportRule, copyYaml,
      newRule, regenId,
    };
  }
}).mount('#app');
