// sigma-data.js — all static reference data for the Sigma Rule Builder
// Logsource presets, field definitions, MITRE ATT&CK tags, modifiers,
// and SigmaHQ community rule browser tree

window.SIGMA_DATA = {

  // ─── LOGSOURCE PRESETS ────────────────────────────────────────────────────
  logsources: [
    {
      id: 'sysmon_process',
      label: 'Sysmon — Process Creation',
      group: 'Sysmon',
      category: 'process_creation', product: 'windows', service: 'sysmon',
      fields: ['Image','CommandLine','ParentImage','ParentCommandLine','OriginalFileName',
               'CurrentDirectory','User','LogonId','IntegrityLevel','Hashes','ProcessGuid',
               'ProcessId','ParentProcessGuid','ParentProcessId','Company','Description',
               'FileVersion','Product']
    },
    {
      id: 'sysmon_network',
      label: 'Sysmon — Network Connection',
      group: 'Sysmon',
      category: 'network_connection', product: 'windows', service: 'sysmon',
      fields: ['Image','User','Protocol','Initiated','SourceIsIpv6','SourceIp',
               'SourceHostname','SourcePort','SourcePortName','DestinationIsIpv6',
               'DestinationIp','DestinationHostname','DestinationPort','DestinationPortName',
               'ProcessId','ProcessGuid']
    },
    {
      id: 'sysmon_file',
      label: 'Sysmon — File Creation',
      group: 'Sysmon',
      category: 'file_event', product: 'windows', service: 'sysmon',
      fields: ['Image','TargetFilename','CreationUtcTime','ProcessGuid','ProcessId','User','Hashes']
    },
    {
      id: 'sysmon_registry',
      label: 'Sysmon — Registry Event',
      group: 'Sysmon',
      category: 'registry_event', product: 'windows', service: 'sysmon',
      fields: ['EventType','Image','ProcessGuid','ProcessId','TargetObject','Details','NewName','User']
    },
    {
      id: 'sysmon_driver',
      label: 'Sysmon — Driver Loaded',
      group: 'Sysmon',
      category: 'driver_load', product: 'windows', service: 'sysmon',
      fields: ['ImageLoaded','Hashes','Signed','Signature','SignatureStatus','ProcessGuid','ProcessId']
    },
    {
      id: 'sysmon_image_load',
      label: 'Sysmon — Image/DLL Load',
      group: 'Sysmon',
      category: 'image_load', product: 'windows', service: 'sysmon',
      fields: ['Image','ImageLoaded','FileVersion','Description','Product','Company',
               'OriginalFileName','Hashes','Signed','Signature','SignatureStatus',
               'ProcessGuid','ProcessId','User']
    },
    {
      id: 'sysmon_pipe',
      label: 'Sysmon — Pipe Event',
      group: 'Sysmon',
      category: 'pipe_created', product: 'windows', service: 'sysmon',
      fields: ['EventType','Image','PipeName','ProcessGuid','ProcessId','User']
    },
    {
      id: 'sysmon_dns',
      label: 'Sysmon — DNS Query',
      group: 'Sysmon',
      category: 'dns_query', product: 'windows', service: 'sysmon',
      fields: ['Image','QueryName','QueryStatus','QueryResults','ProcessGuid','ProcessId','User']
    },
    {
      id: 'linux_auditd',
      label: 'Linux — Auditd',
      group: 'Linux',
      category: 'process_creation', product: 'linux', service: 'auditd',
      fields: ['type','exe','comm','syscall','a0','a1','a2','a3','uid','gid','euid','egid',
               'pid','ppid','cwd','name','nametype','proctitle','key']
    },
    {
      id: 'linux_syslog',
      label: 'Linux — Syslog',
      group: 'Linux',
      category: null, product: 'linux', service: 'syslog',
      fields: ['message','hostname','program','pid','facility','severity','timestamp','user','process']
    },
    {
      id: 'linux_auth',
      label: 'Linux — Auth Log',
      group: 'Linux',
      category: null, product: 'linux', service: 'auth',
      fields: ['message','hostname','program','pid','user','rhost','session','tty','type']
    },
    {
      id: 'dns_query',
      label: 'DNS — Query Log',
      group: 'DNS',
      category: 'dns', product: null, service: null,
      fields: ['query','answer','QueryName','QueryType','QueryStatus','QueryResults',
               'src_ip','dst_ip','rcode','qtype','answers','ttl','domain','subdomain','tld']
    },
    {
      id: 'defender_alert',
      label: 'Windows Defender — Alert',
      group: 'Defender',
      category: 'antivirus', product: 'windows', service: 'windefend',
      fields: ['ThreatName','Severity','Category','Action','ActionSuccess','Path',
               'ProcessName','Detection','SignatureVersion','EngineVersion','ProductVersion',
               'User','ComputerName']
    },
    {
      id: 'defender_atp',
      label: 'Microsoft Defender for Endpoint',
      group: 'Defender',
      category: null, product: 'windows', service: 'microsoft-windows-windows-defender',
      fields: ['EventID','Image','CommandLine','ParentImage','FileName','FolderPath',
               'SHA256','MD5','RemoteUrl','RemoteIP','RemotePort',
               'InitiatingProcessAccountName','InitiatingProcessFileName',
               'InitiatingProcessCommandLine','AlertName','AlertSeverity','Category']
    },
    {
      id: 'windows_security',
      label: 'Windows — Security Log',
      group: 'Windows',
      category: null, product: 'windows', service: 'security',
      fields: ['EventID','SubjectUserName','SubjectDomainName','SubjectLogonId',
               'TargetUserName','TargetDomainName','TargetLogonId','LogonType',
               'WorkstationName','IpAddress','IpPort','ProcessName','ObjectName',
               'ObjectType','AccessMask','PrivilegeList','ShareName','Status','FailureReason']
    }
  ],

  // ─── LOGSOURCE GROUPS (computed once, used in <optgroup>) ─────────────────
  get logsourceGroups() {
    if (this._logsourceGroups) return this._logsourceGroups;
    const groups = {};
    this.logsources.forEach(ls => {
      const g = ls.group || 'Other';
      if (!groups[g]) groups[g] = [];
      groups[g].push(ls);
    });
    this._logsourceGroups = groups;
    return groups;
  },

  // ─── DETECTION MODIFIERS ─────────────────────────────────────────────────
  modifiers: [
    { value: '',              label: '= (exact match)' },
    { value: 'contains',      label: 'contains' },
    { value: 'startswith',    label: 'startswith' },
    { value: 'endswith',      label: 'endswith' },
    { value: 're',            label: 're (regex)' },
    { value: 'cidr',          label: 'cidr' },
    { value: 'all',           label: 'all (AND list)' },
    { value: 'base64',        label: 'base64' },
    { value: 'base64offset',  label: 'base64offset' },
    { value: 'wide',          label: 'wide (UTF-16)' },
    { value: 'windash',       label: 'windash' },
    { value: 'contains|all',  label: 'contains|all' },
    { value: 'contains|windash', label: 'contains|windash' },
  ],

  // ─── CONDITION TEMPLATES ──────────────────────────────────────────────────
  conditionTemplates: [
    { label: 'Single selection',       value: 'selection' },
    { label: 'selection AND NOT filter', value: 'selection and not filter' },
    { label: '1 of selection*',        value: '1 of selection*' },
    { label: 'all of selection*',      value: 'all of selection*' },
    { label: '1 of them',              value: '1 of them' },
    { label: 'all of them',            value: 'all of them' },
    { label: 'Custom…',                value: '__custom__' },
  ],

  statusOptions: ['stable', 'test', 'experimental', 'deprecated', 'unsupported'],
  levelOptions:  ['informational', 'low', 'medium', 'high', 'critical'],

  // ─── MITRE ATT&CK TAGS ───────────────────────────────────────────────────
  mitreTags: [
    { id: 'T1078',     name: 'Valid Accounts' },
    { id: 'T1190',     name: 'Exploit Public-Facing Application' },
    { id: 'T1566',     name: 'Phishing' },
    { id: 'T1566.001', name: 'Phishing: Spearphishing Attachment' },
    { id: 'T1566.002', name: 'Phishing: Spearphishing Link' },
    { id: 'T1059',     name: 'Command and Scripting Interpreter' },
    { id: 'T1059.001', name: 'Command and Scripting Interpreter: PowerShell' },
    { id: 'T1059.003', name: 'Command and Scripting Interpreter: Windows Command Shell' },
    { id: 'T1059.004', name: 'Command and Scripting Interpreter: Unix Shell' },
    { id: 'T1059.005', name: 'Command and Scripting Interpreter: Visual Basic' },
    { id: 'T1059.007', name: 'Command and Scripting Interpreter: JavaScript' },
    { id: 'T1106',     name: 'Native API' },
    { id: 'T1204',     name: 'User Execution' },
    { id: 'T1569',     name: 'System Services' },
    { id: 'T1569.002', name: 'System Services: Service Execution' },
    { id: 'T1053',     name: 'Scheduled Task/Job' },
    { id: 'T1053.005', name: 'Scheduled Task/Job: Scheduled Task' },
    { id: 'T1136',     name: 'Create Account' },
    { id: 'T1547',     name: 'Boot or Logon Autostart Execution' },
    { id: 'T1547.001', name: 'Boot or Logon Autostart Execution: Registry Run Keys' },
    { id: 'T1543',     name: 'Create or Modify System Process' },
    { id: 'T1543.003', name: 'Create or Modify System Process: Windows Service' },
    { id: 'T1546',     name: 'Event Triggered Execution' },
    { id: 'T1055',     name: 'Process Injection' },
    { id: 'T1055.001', name: 'Process Injection: DLL Injection' },
    { id: 'T1055.012', name: 'Process Injection: Process Hollowing' },
    { id: 'T1548',     name: 'Abuse Elevation Control Mechanism' },
    { id: 'T1548.002', name: 'Abuse Elevation Control Mechanism: Bypass UAC' },
    { id: 'T1027',     name: 'Obfuscated Files or Information' },
    { id: 'T1036',     name: 'Masquerading' },
    { id: 'T1070',     name: 'Indicator Removal' },
    { id: 'T1070.001', name: 'Indicator Removal: Clear Windows Event Logs' },
    { id: 'T1112',     name: 'Modify Registry' },
    { id: 'T1140',     name: 'Deobfuscate/Decode Files or Information' },
    { id: 'T1218',     name: 'System Binary Proxy Execution' },
    { id: 'T1218.005', name: 'System Binary Proxy Execution: Mshta' },
    { id: 'T1218.010', name: 'System Binary Proxy Execution: Regsvr32' },
    { id: 'T1218.011', name: 'System Binary Proxy Execution: Rundll32' },
    { id: 'T1562',     name: 'Impair Defenses' },
    { id: 'T1562.001', name: 'Impair Defenses: Disable or Modify Tools' },
    { id: 'T1003',     name: 'OS Credential Dumping' },
    { id: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory' },
    { id: 'T1110',     name: 'Brute Force' },
    { id: 'T1555',     name: 'Credentials from Password Stores' },
    { id: 'T1558',     name: 'Steal or Forge Kerberos Tickets' },
    { id: 'T1558.003', name: 'Steal or Forge Kerberos Tickets: Kerberoasting' },
    { id: 'T1016',     name: 'System Network Configuration Discovery' },
    { id: 'T1018',     name: 'Remote System Discovery' },
    { id: 'T1033',     name: 'System Owner/User Discovery' },
    { id: 'T1057',     name: 'Process Discovery' },
    { id: 'T1082',     name: 'System Information Discovery' },
    { id: 'T1083',     name: 'File and Directory Discovery' },
    { id: 'T1518',     name: 'Software Discovery' },
    { id: 'T1021',     name: 'Remote Services' },
    { id: 'T1021.001', name: 'Remote Services: Remote Desktop Protocol' },
    { id: 'T1021.002', name: 'Remote Services: SMB/Windows Admin Shares' },
    { id: 'T1021.006', name: 'Remote Services: Windows Remote Management' },
    { id: 'T1047',     name: 'Windows Management Instrumentation' },
    { id: 'T1550',     name: 'Use Alternate Authentication Material' },
    { id: 'T1550.002', name: 'Use Alternate Authentication Material: Pass the Hash' },
    { id: 'T1005',     name: 'Data from Local System' },
    { id: 'T1056',     name: 'Input Capture' },
    { id: 'T1113',     name: 'Screen Capture' },
    { id: 'T1071',     name: 'Application Layer Protocol' },
    { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols' },
    { id: 'T1071.004', name: 'Application Layer Protocol: DNS' },
    { id: 'T1095',     name: 'Non-Application Layer Protocol' },
    { id: 'T1105',     name: 'Ingress Tool Transfer' },
    { id: 'T1132',     name: 'Data Encoding' },
    { id: 'T1041',     name: 'Exfiltration Over C2 Channel' },
    { id: 'T1048',     name: 'Exfiltration Over Alternative Protocol' },
    { id: 'T1486',     name: 'Data Encrypted for Impact' },
    { id: 'T1490',     name: 'Inhibit System Recovery' },
    { id: 'T1489',     name: 'Service Stop' },
  ],

  // ─── SIGMAHQ COMMUNITY BROWSER ───────────────────────────────────────────
  // Defines the browsable categories and their GitHub API paths.
  // Files are fetched on-demand — one tree API call per category when opened.
  // Raw rule content is fetched only when the user clicks a specific rule.

  SIGMAHQ_REPO: 'SigmaHQ/sigma',
  SIGMAHQ_BRANCH: 'master',
  SIGMAHQ_RAW_BASE: 'https://raw.githubusercontent.com/SigmaHQ/sigma/master/',
  SIGMAHQ_API_BASE: 'https://api.github.com/repos/SigmaHQ/sigma/',

  communityCategories: [
    // ── Windows / Sysmon ──────────────────────────────────────────────────
    { id: 'win_proc',    label: 'Windows — Process Creation',     path: 'rules/windows/process_creation',    group: 'Windows' },
    { id: 'win_net',     label: 'Windows — Network Connection',   path: 'rules/windows/network_connection',   group: 'Windows' },
    { id: 'win_reg',     label: 'Windows — Registry',             path: 'rules/windows/registry',             group: 'Windows' },
    { id: 'win_file',    label: 'Windows — File Events',          path: 'rules/windows/file',                 group: 'Windows' },
    { id: 'win_imgload', label: 'Windows — Image Load',           path: 'rules/windows/image_load',           group: 'Windows' },
    { id: 'win_driver',  label: 'Windows — Driver Load',          path: 'rules/windows/driver_load',          group: 'Windows' },
    { id: 'win_pipe',    label: 'Windows — Pipe Created',         path: 'rules/windows/pipe_created',         group: 'Windows' },
    { id: 'win_dns',     label: 'Windows — DNS Query',            path: 'rules/windows/dns_query',            group: 'Windows' },
    { id: 'win_ps',      label: 'Windows — PowerShell',           path: 'rules/windows/powershell',           group: 'Windows' },
    { id: 'win_wmi',     label: 'Windows — WMI Event',            path: 'rules/windows/wmi_event',            group: 'Windows' },
    { id: 'win_builtin', label: 'Windows — Builtin Logs',         path: 'rules/windows/builtin',              group: 'Windows' },
    { id: 'win_thread',  label: 'Windows — Remote Thread',        path: 'rules/windows/create_remote_thread', group: 'Windows' },
    { id: 'win_access',  label: 'Windows — Process Access',       path: 'rules/windows/process_access',       group: 'Windows' },
    // ── Linux ─────────────────────────────────────────────────────────────
    { id: 'lx_proc',     label: 'Linux — Process Creation',       path: 'rules/linux/process_creation',       group: 'Linux' },
    { id: 'lx_net',      label: 'Linux — Network Connection',     path: 'rules/linux/network_connection',     group: 'Linux' },
    { id: 'lx_file',     label: 'Linux — File Events',            path: 'rules/linux/file_event',             group: 'Linux' },
    { id: 'lx_auditd',   label: 'Linux — Auditd',                 path: 'rules/linux/auditd',                 group: 'Linux' },
    { id: 'lx_builtin',  label: 'Linux — Builtin',                path: 'rules/linux/builtin',                group: 'Linux' },
    // ── Network / DNS ─────────────────────────────────────────────────────
    { id: 'net_dns',     label: 'Network — DNS',                  path: 'rules/network/dns',                  group: 'Network' },
    { id: 'net_fw',      label: 'Network — Firewall',             path: 'rules/network/firewall',             group: 'Network' },
    { id: 'net_zeek',    label: 'Network — Zeek',                 path: 'rules/network/zeek',                 group: 'Network' },
    // ── Cloud ─────────────────────────────────────────────────────────────
    { id: 'cloud_aws',   label: 'Cloud — AWS CloudTrail',         path: 'rules/cloud/aws',                    group: 'Cloud' },
    { id: 'cloud_az',    label: 'Cloud — Azure',                  path: 'rules/cloud/azure',                  group: 'Cloud' },
    { id: 'cloud_gcp',   label: 'Cloud — GCP',                    path: 'rules/cloud/gcp',                    group: 'Cloud' },
    { id: 'cloud_m365',  label: 'Cloud — Microsoft 365',          path: 'rules/cloud/m365',                   group: 'Cloud' },
    // ── Application ───────────────────────────────────────────────────────
    { id: 'app_web',     label: 'Application — Web Server',       path: 'rules/application',                  group: 'Application' },
  ],

  // ─── LOCAL PINNED TEMPLATES ───────────────────────────────────────────────
  // Fallback starters served from the same repo (no rate limit).
  pinnedTemplates: [
    { id: 'sysmon_powershell', label: 'Sysmon — Suspicious PowerShell', file: 'templates/sysmon-suspicious-powershell.yml', group: 'Pinned' },
    { id: 'sysmon_lolbas',     label: 'Sysmon — LOLBAS Proxy',          file: 'templates/sysmon-lolbas-proxy.yml',           group: 'Pinned' },
    { id: 'sysmon_net_c2',     label: 'Sysmon — Network C2 Beacon',     file: 'templates/sysmon-network-c2.yml',             group: 'Pinned' },
    { id: 'linux_revshell',    label: 'Linux — Reverse Shell',          file: 'templates/linux-reverse-shell.yml',           group: 'Pinned' },
    { id: 'linux_sudo',        label: 'Linux — Sudo Abuse',             file: 'templates/linux-sudo-abuse.yml',              group: 'Pinned' },
    { id: 'dns_dga',           label: 'DNS — DGA Activity',             file: 'templates/dns-dga-activity.yml',              group: 'Pinned' },
    { id: 'dns_tunnel',        label: 'DNS — Tunneling',                file: 'templates/dns-tunneling.yml',                 group: 'Pinned' },
    { id: 'def_malware',       label: 'Defender — Malware Alert',       file: 'templates/defender-malware-alert.yml',        group: 'Pinned' },
    { id: 'def_disabled',      label: 'Defender — Protection Disabled', file: 'templates/defender-disabled.yml',             group: 'Pinned' },
  ],
};
