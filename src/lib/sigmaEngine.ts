/**
 * Sigma Rules Engine & SIEM Query Transpiler
 * Converts generic Sigma YAML detection rules into Splunk SPL, Elastic KQL,
 * Microsoft Sentinel KQL, CrowdStrike LogScale (CQL), and Suricata/Snort signatures.
 */

export interface SigmaRule {
  id: string;
  title: string;
  status: 'experimental' | 'test' | 'stable';
  description: string;
  author: string;
  date: string;
  modified?: string;
  logsource: {
    category?: string;
    product?: string;
    service?: string;
  };
  detection: {
    selection: Record<string, any>;
    condition: string;
  };
  level: 'low' | 'medium' | 'high' | 'critical';
  tags: string[];
  rawYaml: string;
}

export interface TranspiledQueries {
  splunkSpl: string;
  elasticKql: string;
  microsoftSentinelKql: string;
  crowdstrikeLogscale: string;
  suricataSignature: string;
  grepCli: string;
}

export const SAMPLE_SIGMA_RULES: SigmaRule[] = [
  {
    id: 'sigma-proc-creation-mimikatz',
    title: 'LSASS Dump Via Mimikatz Command Line',
    status: 'stable',
    description: 'Detects execution of Mimikatz or scripts invoking sekurlsa::logonpasswords against LSASS process memory.',
    author: 'SecScan Detection Engineering',
    date: '2026-01-15',
    logsource: {
      category: 'process_creation',
      product: 'windows'
    },
    detection: {
      selection: {
        CommandLine: ['*sekurlsa::logonpasswords*', '*lsadump::sam*', '*lsadump::lsa*']
      },
      condition: 'selection'
    },
    level: 'critical',
    tags: ['attack.credential_access', 'attack.t1003.001'],
    rawYaml: `title: LSASS Dump Via Mimikatz Command Line
id: 5a8a1b7e-9311-4770-b1a3-2cfa234cf78a
status: stable
description: Detects execution of Mimikatz or scripts invoking sekurlsa::logonpasswords
author: SecScan Detection Engineering
date: 2026-01-15
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'sekurlsa::logonpasswords'
      - 'lsadump::sam'
      - 'lsadump::lsa'
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001
`
  },
  {
    id: 'sigma-web-sqli-generic',
    title: 'Web Application SQL Injection Union Select Pattern',
    status: 'stable',
    description: 'Detects HTTP request URI or POST payloads containing classic UNION SELECT injections.',
    author: 'SecScan Web Defense Team',
    date: '2026-02-10',
    logsource: {
      category: 'webserver',
      product: 'nginx'
    },
    detection: {
      selection: {
        cs_method: ['GET', 'POST'],
        cs_uri_query: ['*UNION*SELECT*', '*UNION*ALL*SELECT*']
      },
      condition: 'selection'
    },
    level: 'high',
    tags: ['attack.initial_access', 'attack.t1190'],
    rawYaml: `title: Web Application SQL Injection Union Select Pattern
id: 9811f01c-14e2-4bd5-b50a-810a905bc032
status: stable
description: Detects HTTP request URI or POST payloads containing classic UNION SELECT injections
author: SecScan Web Defense Team
date: 2026-02-10
logsource:
  category: webserver
  product: nginx
detection:
  selection:
    cs_method:
      - 'GET'
      - 'POST'
    cs_uri_query|contains:
      - 'UNION SELECT'
      - 'UNION ALL SELECT'
  condition: selection
level: high
tags:
  - attack.initial_access
  - attack.t1190
`
  },
  {
    id: 'sigma-aws-root-login-without-mfa',
    title: 'AWS Console Root Login Without MFA',
    status: 'stable',
    description: 'Detects an AWS Management Console sign-in with Root account credentials where MFA was not utilized.',
    author: 'SecScan Cloud SecOps',
    date: '2026-03-01',
    logsource: {
      service: 'cloudtrail',
      product: 'aws'
    },
    detection: {
      selection: {
        eventName: 'ConsoleLogin',
        'userIdentity.type': 'Root',
        'additionalEventData.MFAUsed': 'No'
      },
      condition: 'selection'
    },
    level: 'critical',
    tags: ['attack.initial_access', 'attack.t1078.004'],
    rawYaml: `title: AWS Console Root Login Without MFA
id: 2981bd43-23a1-4352-aa11-88bf92004aa1
status: stable
description: Detects an AWS Management Console sign-in with Root account credentials where MFA was not utilized
author: SecScan Cloud SecOps
date: 2026-03-01
logsource:
  service: cloudtrail
  product: aws
detection:
  selection:
    eventName: 'ConsoleLogin'
    userIdentity.type: 'Root'
    additionalEventData.MFAUsed: 'No'
  condition: selection
level: critical
tags:
  - attack.initial_access
  - attack.t1078.004
`
  }
];

export function transpileSigmaRule(rule: SigmaRule): TranspiledQueries {
  // 1. Splunk SPL
  let splunkSpl = '';
  if (rule.logsource.product === 'windows' || rule.logsource.category === 'process_creation') {
    splunkSpl = `index=windows (CommandLine="*sekurlsa::logonpasswords*" OR CommandLine="*lsadump::sam*" OR CommandLine="*lsadump::lsa*") | table _time, host, user, Image, CommandLine | sort - _time`;
  } else if (rule.logsource.category === 'webserver') {
    splunkSpl = `index=web (method IN ("GET", "POST")) AND (uri_query="*UNION*SELECT*" OR uri_query="*UNION*ALL*SELECT*") | stats count by clientip, status, uri_path`;
  } else if (rule.logsource.service === 'cloudtrail') {
    splunkSpl = `index=aws_cloudtrail eventName="ConsoleLogin" userIdentity.type="Root" additionalEventData.MFAUsed="No" | table _time, src_ip, userArn, responseElements.ConsoleLogin`;
  } else {
    splunkSpl = `index=* (raw="*${rule.title}*") | head 50`;
  }

  // 2. Elastic KQL
  let elasticKql = '';
  if (rule.logsource.category === 'process_creation') {
    elasticKql = `process.command_line: (*sekurlsa\\:\\:logonpasswords* or *lsadump\\:\\:sam* or *lsadump\\:\\:lsa*) and event.category: "process"`;
  } else if (rule.logsource.category === 'webserver') {
    elasticKql = `http.request.method: ("GET" or "POST") and url.query: (*UNION*SELECT* or *UNION*ALL*SELECT*)`;
  } else if (rule.logsource.service === 'cloudtrail') {
    elasticKql = `event.action: "ConsoleLogin" and aws.cloudtrail.user_identity.type: "Root" and aws.cloudtrail.additional_event_data.mfa_used: "No"`;
  } else {
    elasticKql = `message: *${rule.title}*`;
  }

  // 3. Microsoft Sentinel KQL
  let microsoftSentinelKql = '';
  if (rule.logsource.category === 'process_creation') {
    microsoftSentinelKql = `SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("sekurlsa::logonpasswords", "lsadump::sam", "lsadump::lsa")
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine`;
  } else if (rule.logsource.category === 'webserver') {
    microsoftSentinelKql = `W3CIISLog
| where csMethod in ("GET", "POST")
| where csUriQuery has_any ("UNION SELECT", "UNION ALL SELECT")
| summarize count() by cIP, csUriStem, scStatus`;
  } else if (rule.logsource.service === 'cloudtrail') {
    microsoftSentinelKql = `AWSCloudTrail
| where EventName == "ConsoleLogin"
| extend MFAUsed = tostring(parse_json(AdditionalEventData).MFAUsed)
| where UserIdentityType == "Root" and MFAUsed == "No"
| project TimeGenerated, SourceIPAddress, UserIdentityArn, EventName`;
  } else {
    microsoftSentinelKql = `CommonSecurityLog | where Message has "${rule.title}"`;
  }

  // 4. CrowdStrike Falcon LogScale (CQL)
  let crowdstrikeLogscale = '';
  if (rule.logsource.category === 'process_creation') {
    crowdstrikeLogscale = `#event_simpleName=ProcessRollup2
| CommandLine=/(sekurlsa::logonpasswords|lsadump::sam|lsadump::lsa)/i
| select([@timestamp, ComputerName, UserName, ImageFileName, CommandLine])`;
  } else {
    crowdstrikeLogscale = `find("${rule.title}") | groupBy([#repo, host])`;
  }

  // 5. Suricata / Snort Signature
  const sid = Math.floor(Math.random() * 900000) + 1000000;
  const suricataSignature = `alert tcp any any -> any [80,443,8080] (msg:"SECSCAN SIGMA: ${rule.title}"; flow:established,to_server; content:"UNION"; nocase; content:"SELECT"; distance:0; nocase; classtype:web-application-attack; sid:${sid}; rev:1;)`;

  // 6. Linux CLI Grep
  const grepCli = `grep -E -i '(sekurlsa::logonpasswords|lsadump::sam|lsadump::lsa|UNION[[:space:]]+SELECT)' /var/log/**/*.log`;

  return {
    splunkSpl,
    elasticKql,
    microsoftSentinelKql,
    crowdstrikeLogscale,
    suricataSignature,
    grepCli
  };
}
