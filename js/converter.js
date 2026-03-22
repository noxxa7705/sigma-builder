// converter.js — Sigma Rule → SPL / KQL / EQL converter
// Pure client-side, no dependencies. Exported as window.SigmaConverter.

(function () {
  'use strict';

  // ── Logsource map ──────────────────────────────────────────────────────────

  var LOGSOURCE_MAP = {
    spl: {
      'windows/sysmon':      'index=sysmon',
      'windows/security':    'index=wineventlog sourcetype=WinEventLog:Security',
      'windows/system':      'index=wineventlog sourcetype=WinEventLog:System',
      'windows/application': 'index=wineventlog sourcetype=WinEventLog:Application',
      'windows/powershell':  'index=wineventlog source=WinEventLog:Windows PowerShell',
      'linux/syslog':        'index=linux_logs sourcetype=syslog',
      'linux/auth':          'index=linux_logs sourcetype=linux_secure',
      'network/dns':         'index=network sourcetype=stream:dns',
      'network/firewall':    'index=network sourcetype=stream:tcp',
      'cloud/azure':         'index=azure',
      'process_creation':    'index=sysmon EventCode=1',
      'network_connection':  'index=sysmon EventCode=3',
      'file_event':          'index=sysmon EventCode=11',
      'registry_event':      'index=sysmon EventCode=12 OR EventCode=13 OR EventCode=14',
      'dns_query':           'index=sysmon EventCode=22',
    },
    kql: {
      'windows/sysmon':      'SysmonEvent',
      'windows/security':    'SecurityEvent',
      'windows/system':      'Event',
      'process_creation':    'DeviceProcessEvents',
      'network_connection':  'DeviceNetworkEvents',
      'file_event':          'DeviceFileEvents',
      'registry_event':      'DeviceRegistryEvents',
      'dns_query':           'DeviceNetworkEvents | where ActionType == "DnsQueryResponse"',
      'cloud/azure':         'AzureActivity',
      'cloud/azuread':       'AuditLogs',
      'network/dns':         'DnsEvents',
      'network/firewall':    'AzureNetworkAnalytics_CL',
      'authentication':      'SigninLogs',
    },
    eql: {
      'process_creation':   'process',
      'network_connection': 'network',
      'file_event':         'file',
      'registry_event':     'registry',
      'dns_query':          'network',
      'windows/security':   'authentication',
      'authentication':     'authentication',
    },
  };

  // ── Logsource key resolution ───────────────────────────────────────────────

  function logsourceKey(logsource) {
    if (!logsource) return null;
    var cat     = (logsource.category || '').trim().toLowerCase();
    var product = (logsource.product  || '').trim().toLowerCase();
    var service = (logsource.service  || '').trim().toLowerCase();

    // Try product/service first
    if (product && service) {
      var ps = product + '/' + service;
      return ps;
    }
    // Try product/category
    if (product && cat) {
      return product + '/' + cat;
    }
    // Category alone
    if (cat) return cat;
    // Product alone
    if (product) return product;
    return null;
  }

  function resolveLogsource(logsource, backend) {
    var map = LOGSOURCE_MAP[backend] || {};
    var key = logsourceKey(logsource);
    if (!key) return null;
    // Direct lookup
    if (map[key]) return map[key];
    // Try just category
    var cat = (logsource.category || '').trim().toLowerCase();
    if (cat && map[cat]) return map[cat];
    // Try just product
    var prod = (logsource.product || '').trim().toLowerCase();
    if (prod && map[prod]) return map[prod];
    return null;
  }

  // ── Value escaping helpers ─────────────────────────────────────────────────

  function escSpl(v) {
    // Escape backslash and double-quote inside SPL quoted strings
    return String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  }

  function escKql(v) {
    return String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  }

  function escEql(v) {
    return String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  }

  // ── windash expansion ──────────────────────────────────────────────────────

  function windashExpand(values) {
    var expanded = [];
    values.forEach(function (v) {
      expanded.push(v);
      var replaced = String(v).replace(/-/g, '/');
      if (replaced !== String(v)) expanded.push(replaced);
    });
    return expanded;
  }

  // ── Per-field condition rendering ──────────────────────────────────────────

  /**
   * renderField returns { parts: string[], note: string }
   * parts are individual condition strings (joined later with AND or OR)
   */
  function renderFieldSpl(field, modifier, values, notes) {
    var f = field;
    var mod = (modifier || '').toLowerCase();

    // Unsupported modifiers that need notes
    if (mod === 'base64' || mod === 'base64offset') {
      notes.push('base64-encoded field "' + f + '" — manual conversion required');
      return ['/* base64-encoded — manual conversion required */'];
    }
    if (mod === 'wide') {
      notes.push('wide-string field "' + f + '" — tool cannot convert');
      return ['/* wide string — tool cannot convert */'];
    }

    if (mod === 'windash') {
      values = windashExpand(values);
      mod = '';
    }

    var containsAll = mod === 'contains|all' || mod === 'all';
    var useAnd      = containsAll;
    var effectiveMod = mod.replace('|all', '');

    var parts = values.filter(function (v) { return v !== '' && v !== null && v !== undefined; }).map(function (v) {
      var sv = String(v);
      if (effectiveMod === 'contains') {
        return f + '="*' + escSpl(sv) + '*"';
      } else if (effectiveMod === 'startswith') {
        return f + '="' + escSpl(sv) + '*"';
      } else if (effectiveMod === 'endswith') {
        return f + '="*' + escSpl(sv) + '"';
      } else if (effectiveMod === 're') {
        return 'match(' + f + ', "' + escSpl(sv) + '")';
      } else if (effectiveMod === 'cidr') {
        return 'cidrmatch(' + f + ', "' + escSpl(sv) + '")';
      } else {
        // exact / empty modifier
        return f + '="' + escSpl(sv) + '"';
      }
    });

    if (parts.length === 0) return [];
    if (parts.length === 1) return parts;

    var joinOp = useAnd ? ' AND ' : ' OR ';
    return ['(' + parts.join(joinOp) + ')'];
  }

  function renderFieldKql(field, modifier, values, notes) {
    var f = field;
    var mod = (modifier || '').toLowerCase();

    if (mod === 'base64' || mod === 'base64offset') {
      notes.push('base64-encoded field "' + f + '" — manual conversion required');
      return ['// base64-encoded — manual conversion required'];
    }
    if (mod === 'wide') {
      notes.push('wide-string field "' + f + '" — tool cannot convert');
      return ['// wide string — tool cannot convert'];
    }

    if (mod === 'windash') {
      values = windashExpand(values);
      mod = '';
    }

    var containsAll = mod === 'contains|all' || mod === 'all';
    var useAnd      = containsAll;
    var effectiveMod = mod.replace('|all', '');

    var parts = values.filter(function (v) { return v !== '' && v !== null && v !== undefined; }).map(function (v) {
      var sv = String(v);
      if (effectiveMod === 'contains') {
        return f + ' contains "' + escKql(sv) + '"';
      } else if (effectiveMod === 'startswith') {
        return f + ' startswith "' + escKql(sv) + '"';
      } else if (effectiveMod === 'endswith') {
        return f + ' endswith "' + escKql(sv) + '"';
      } else if (effectiveMod === 're') {
        return f + ' matches regex "' + escKql(sv) + '"';
      } else if (effectiveMod === 'cidr') {
        return 'ipv4_is_in_range(' + f + ', "' + escKql(sv) + '")';
      } else {
        return f + ' == "' + escKql(sv) + '"';
      }
    });

    if (parts.length === 0) return [];
    if (parts.length === 1) return parts;

    var joinOp = useAnd ? ' and ' : ' or ';
    return ['(' + parts.join(joinOp) + ')'];
  }

  function renderFieldEql(field, modifier, values, notes) {
    var f = field;
    var mod = (modifier || '').toLowerCase();

    if (mod === 'base64' || mod === 'base64offset') {
      notes.push('base64-encoded field "' + f + '" — manual conversion required');
      return ['// base64-encoded — manual conversion required'];
    }
    if (mod === 'wide') {
      notes.push('wide-string field "' + f + '" — tool cannot convert');
      return ['// wide string — tool cannot convert'];
    }

    if (mod === 'windash') {
      values = windashExpand(values);
      mod = '';
    }

    var containsAll = mod === 'contains|all' || mod === 'all';
    var useAnd      = containsAll;
    var effectiveMod = mod.replace('|all', '');

    var parts = values.filter(function (v) { return v !== '' && v !== null && v !== undefined; }).map(function (v) {
      var sv = String(v);
      if (effectiveMod === 'contains') {
        return f + ' like "*' + escEql(sv) + '*"';
      } else if (effectiveMod === 'startswith') {
        return f + ' like "' + escEql(sv) + '*"';
      } else if (effectiveMod === 'endswith') {
        return f + ' like "*' + escEql(sv) + '"';
      } else if (effectiveMod === 're') {
        return f + ': /' + sv + '/';
      } else if (effectiveMod === 'cidr') {
        return 'cidrMatch(' + f + ', "' + escEql(sv) + '")';
      } else {
        return f + ' == "' + escEql(sv) + '"';
      }
    });

    if (parts.length === 0) return [];
    if (parts.length === 1) return parts;

    var joinOp = useAnd ? ' and ' : ' or ';
    return ['(' + parts.join(joinOp) + ')'];
  }

  // ── Group rendering ────────────────────────────────────────────────────────

  function renderGroupSpl(group, notes) {
    if (group.type === 'keywords') {
      var kws = (group.keywords || []).filter(Boolean);
      if (kws.length === 0) return '';
      return 'search ' + kws.map(function (k) { return '"' + escSpl(k) + '"'; }).join(' OR ');
    }

    var conditions = [];
    (group.fields || []).forEach(function (f) {
      if (!f.field) return;
      var vals = (f.values || []).filter(function (v) { return v !== '' && v !== null && v !== undefined; });
      if (vals.length === 0) return;
      var parts = renderFieldSpl(f.field, f.modifier, vals, notes);
      conditions = conditions.concat(parts);
    });

    if (conditions.length === 0) return '';
    if (conditions.length === 1) return conditions[0];
    return '(' + conditions.join(' AND ') + ')';
  }

  function renderGroupKql(group, notes) {
    if (group.type === 'keywords') {
      var kws = (group.keywords || []).filter(Boolean);
      if (kws.length === 0) return '';
      return kws.map(function (k) { return '* contains "' + escKql(k) + '"'; }).join(' or ');
    }

    var conditions = [];
    (group.fields || []).forEach(function (f) {
      if (!f.field) return;
      var vals = (f.values || []).filter(function (v) { return v !== '' && v !== null && v !== undefined; });
      if (vals.length === 0) return;
      var parts = renderFieldKql(f.field, f.modifier, vals, notes);
      conditions = conditions.concat(parts);
    });

    if (conditions.length === 0) return '';
    if (conditions.length === 1) return conditions[0];
    return '(' + conditions.join(' and ') + ')';
  }

  function renderGroupEql(group, notes) {
    if (group.type === 'keywords') {
      var kws = (group.keywords || []).filter(Boolean);
      if (kws.length === 0) return '';
      return kws.map(function (k) { return '* like "*' + escEql(k) + '*"'; }).join(' or ');
    }

    var conditions = [];
    (group.fields || []).forEach(function (f) {
      if (!f.field) return;
      var vals = (f.values || []).filter(function (v) { return v !== '' && v !== null && v !== undefined; });
      if (vals.length === 0) return;
      var parts = renderFieldEql(f.field, f.modifier, vals, notes);
      conditions = conditions.concat(parts);
    });

    if (conditions.length === 0) return '';
    if (conditions.length === 1) return conditions[0];
    return '(' + conditions.join(' and ') + ')';
  }

  // ── Condition expression parser ────────────────────────────────────────────

  /**
   * Parse and resolve a Sigma condition expression into a rendered query string.
   * groupMap: { groupName -> renderedString }
   * andOp / orOp: ' AND '/' OR ' (SPL) or ' and '/' or ' (KQL/EQL)
   */
  function resolveCondition(condition, groupMap, andOp, orOp, notOp) {
    if (!condition) return '';

    var groupNames = Object.keys(groupMap);

    // Tokenise: split on ( ) and whitespace while preserving tokens
    // We'll do a simple left-to-right substitution pass.

    // Step 1: Handle "1 of them" / "all of them"
    condition = condition.replace(/\b1\s+of\s+them\b/gi, function () {
      var parts = groupNames.map(function (n) { return groupMap[n]; }).filter(Boolean);
      if (parts.length === 0) return '(/* no groups */)';
      return '(' + parts.join(orOp) + ')';
    });

    condition = condition.replace(/\ball\s+of\s+them\b/gi, function () {
      var parts = groupNames.map(function (n) { return groupMap[n]; }).filter(Boolean);
      if (parts.length === 0) return '(/* no groups */)';
      return '(' + parts.join(andOp) + ')';
    });

    // Step 2: Handle "1 of <prefix>*" / "all of <prefix>*"
    condition = condition.replace(/\b1\s+of\s+(\S+)\*/gi, function (_, prefix) {
      var matched = groupNames.filter(function (n) { return n.toLowerCase().indexOf(prefix.toLowerCase()) === 0; });
      var parts = matched.map(function (n) { return groupMap[n]; }).filter(Boolean);
      if (parts.length === 0) return '(/* no groups matching ' + prefix + '* */)';
      return '(' + parts.join(orOp) + ')';
    });

    condition = condition.replace(/\ball\s+of\s+(\S+)\*/gi, function (_, prefix) {
      var matched = groupNames.filter(function (n) { return n.toLowerCase().indexOf(prefix.toLowerCase()) === 0; });
      var parts = matched.map(function (n) { return groupMap[n]; }).filter(Boolean);
      if (parts.length === 0) return '(/* no groups matching ' + prefix + '* */)';
      return '(' + parts.join(andOp) + ')';
    });

    // Step 3: Replace group name tokens with rendered query strings.
    // Sort by length desc to avoid prefix collisions.
    var sortedNames = groupNames.slice().sort(function (a, b) { return b.length - a.length; });
    sortedNames.forEach(function (name) {
      // Replace whole-word occurrences
      var re = new RegExp('(?<![\\w])(\\b' + escapeRegExp(name) + '\\b)(?![\\w*])', 'g');
      condition = condition.replace(re, groupMap[name] || '(/* empty */)');
    });

    // Step 4: Normalise boolean operators
    condition = condition
      .replace(/\bnot\b/gi, notOp)
      .replace(/\band\b/gi, andOp.trim())
      .replace(/\bor\b/gi, orOp.trim());

    return condition;
  }

  function escapeRegExp(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // ── Main convert function ──────────────────────────────────────────────────

  function convert(rule) {
    var splNotes = [];
    var kqlNotes = [];
    var eqlNotes = [];

    try {
      var groups = (rule.detection && rule.detection.groups) ? rule.detection.groups : [];
      var condition = (rule.detection && rule.detection.condition) ? String(rule.detection.condition) : '';

      // Build group maps for each backend
      var splMap = {};
      var kqlMap = {};
      var eqlMap = {};

      groups.forEach(function (g) {
        var name = g.name || 'selection';
        var spl = renderGroupSpl(g, splNotes);
        var kql = renderGroupKql(g, kqlNotes);
        var eql = renderGroupEql(g, eqlNotes);
        if (spl) splMap[name] = spl;
        if (kql) kqlMap[name] = kql;
        if (eql) eqlMap[name] = eql;
      });

      // Resolve condition expressions
      var splCond = resolveCondition(condition, splMap, ' AND ', ' OR ', 'NOT ');
      var kqlCond = resolveCondition(condition, kqlMap, ' and ', ' or ', 'not ');
      var eqlCond = resolveCondition(condition, eqlMap, ' and ', ' or ', 'not ');

      // Logsource prefix
      var logsource = rule.logsource || {};
      var splSource = resolveLogsource(logsource, 'spl');
      var kqlTable  = resolveLogsource(logsource, 'kql');
      var eqlCat    = resolveLogsource(logsource, 'eql');

      // ── SPL ───────────────────────────────────────────────────────────────
      var splHeader = '/* Auto-converted from Sigma \u2014 verify before use */\n';
      var splQuery;
      if (splSource) {
        splQuery = splHeader + splSource + '\n| where ' + (splCond || '(/* no condition */)');
      } else {
        splNotes.unshift('Logsource not mapped — add index/sourcetype manually');
        splQuery = splHeader + '| search ' + (splCond || '(/* no condition */)');
      }

      // ── KQL ───────────────────────────────────────────────────────────────
      var kqlHeader = '// Auto-converted from Sigma \u2014 verify before use\n';
      var kqlQuery;
      if (kqlTable) {
        kqlQuery = kqlHeader + kqlTable + '\n| where ' + (kqlCond || '(/* no condition */)');
      } else {
        kqlNotes.unshift('Logsource not mapped — add table name manually');
        kqlQuery = kqlHeader + '// TODO: add table name\n| where ' + (kqlCond || '(/* no condition */)');
      }

      // ── EQL ───────────────────────────────────────────────────────────────
      var eqlHeader = '// Auto-converted from Sigma \u2014 verify before use\n';
      var eqlQuery;
      var eqlEventType = eqlCat || 'any';
      if (!eqlCat) {
        eqlNotes.unshift('Logsource not mapped — event category defaulted to "any"');
      }
      eqlQuery = eqlHeader + eqlEventType + ' where ' + (eqlCond || '(/* no condition */)');

      return {
        spl: { query: splQuery, note: splNotes.join('; ') },
        kql: { query: kqlQuery, note: kqlNotes.join('; ') },
        eql: { query: eqlQuery, note: eqlNotes.join('; ') },
      };

    } catch (err) {
      var errMsg = 'Conversion error: ' + (err && err.message ? err.message : String(err));
      var fallback = '// Conversion failed — ' + errMsg;
      return {
        spl: { query: fallback, note: errMsg },
        kql: { query: fallback, note: errMsg },
        eql: { query: fallback, note: errMsg },
      };
    }
  }

  // ── Export ─────────────────────────────────────────────────────────────────

  window.SigmaConverter = { convert: convert };

}());
