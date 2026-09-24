import {
  IastHookSensor,
  IastVulnerabilityFinding,
  IastSimulationScenario,
  IastExecutionReport,
  IastTraceStep
} from '../types/iast';
import { ScannedFile, ScanReport } from '../types';

/**
 * Built-in IAST runtime hooks that instrument JavaScript/TypeScript sinks and sources
 */
export const INITIAL_IAST_HOOKS: IastHookSensor[] = [
  {
    id: 'hook-db-sql',
    name: 'SQL Query String Concatenation Interceptor',
    category: 'SQL_DATABASE_SINK',
    targetPackageOrGlobal: 'pg.query / mysql.query / sequelize.query',
    active: true,
    interceptedCallsCount: 142,
    vulnerabilitiesTriggeredCount: 4,
    description: 'Intercepta chamadas SQL no driver em runtime para verificar se fragmentos tainted de requisições HTTP chegam sem parametrização ($1 ou ?).'
  },
  {
    id: 'hook-cmd-exec',
    name: 'OS Command Execution Shell Interceptor',
    category: 'COMMAND_EXEC_SINK',
    targetPackageOrGlobal: 'child_process.exec / child_process.spawn',
    active: true,
    interceptedCallsCount: 89,
    vulnerabilitiesTriggeredCount: 3,
    description: 'Monitora a construção de strings de comando bash/sh/cmd passadas para exec(). Detecta caracteres de encadeamento não sanitizados (; | && $).'
  },
  {
    id: 'hook-path-traversal',
    name: 'File System Path Normalization Guard',
    category: 'FILE_SYSTEM_TRAVERSAL_SINK',
    targetPackageOrGlobal: 'fs.readFile / fs.createReadStream / path.join',
    active: true,
    interceptedCallsCount: 215,
    vulnerabilitiesTriggeredCount: 2,
    description: 'Rastreia caminhos de arquivos resolvidos dinamicamente comparando o diretório base pretendido com a saída de path.resolve().'
  },
  {
    id: 'hook-ssrf-fetch',
    name: 'Outbound HTTP SSRF Sinks Interceptor',
    category: 'SSRF_NETWORK_SINK',
    targetPackageOrGlobal: 'fetch / axios.get / http.request',
    active: true,
    interceptedCallsCount: 178,
    vulnerabilitiesTriggeredCount: 3,
    description: 'Valida URLs de requisições de saída em tempo de execução para barrar destinos em IP loopback (127.0.0.1, localhost) e metadados cloud (169.254.169.254).'
  },
  {
    id: 'hook-dom-eval',
    name: 'DOM Code Evaluator & Script Engine Hook',
    category: 'DOM_XSS_SINK',
    targetPackageOrGlobal: 'eval / Function() / document.write',
    active: true,
    interceptedCallsCount: 64,
    vulnerabilitiesTriggeredCount: 2,
    description: 'Mapeia dados recebidos de APIs e inputs de tela que chegam diretamente em avaliadores de código JavaScript dinâmico em tempo de execução.'
  },
  {
    id: 'hook-deserialization',
    name: 'Object Deserialization & Payload Hook',
    category: 'INSECURE_DESERIALIZATION_SINK',
    targetPackageOrGlobal: 'node-serialize / JSON.parse prototype / yaml.load',
    active: true,
    interceptedCallsCount: 31,
    vulnerabilitiesTriggeredCount: 1,
    description: 'Inspeciona serializações dinâmicas contra poluição de protótipo (__proto__) e instanciação arbitrária de classes não permitidas.'
  }
];

/**
 * Predefined interactive attack simulation scenarios to run runtime emulation
 */
export const IAST_SIMULATION_SCENARIOS: IastSimulationScenario[] = [
  {
    id: 'scenario-sqli',
    name: 'Bypass de Autenticação via Injeção SQL na Rota de Usuário',
    targetRoute: '/api/v1/users/search',
    httpMethod: 'GET',
    inputPayload: {
      searchTerm: "admin' OR '1'='1' --",
      filterRole: "SUPER_ADMIN"
    },
    vulnerabilityTarget: 'pg.query(SELECT * FROM users WHERE username = \'' + "admin' OR '1'='1' --" + '\')',
    attackVectorType: 'SQLi',
    description: 'Emula uma requisição HTTP contendo payload de aspas não tratadas que flui através de controllers até a chamada do driver de banco de dados.'
  },
  {
    id: 'scenario-cmdi',
    name: 'Execução Remota de Comandos (RCE) no Utilitário de Ping',
    targetRoute: '/api/v1/diagnostics/ping',
    httpMethod: 'POST',
    inputPayload: {
      host: '8.8.8.8; cat /etc/passwd #',
      count: '3'
    },
    vulnerabilityTarget: 'child_process.exec(`ping -c 3 ${req.body.host}`)',
    attackVectorType: 'Command Injection',
    description: 'Testa a concatenação direta de parâmetros de formulário em subprocessos do sistema operacional.'
  },
  {
    id: 'scenario-path',
    name: 'Path Traversal na Rota de Download de Relatórios',
    targetRoute: '/api/v1/reports/download',
    httpMethod: 'GET',
    inputPayload: {
      fileName: '../../../../etc/shadow'
    },
    vulnerabilityTarget: 'fs.createReadStream(path.join(REPORT_DIR, req.query.fileName))',
    attackVectorType: 'Path Traversal',
    description: 'Verifica se sequências ../ conseguem escapar da raiz configurada no servidor de arquivos estáticos durante a execução.'
  },
  {
    id: 'scenario-ssrf',
    name: 'SSRF para o Serviço de Metadados de Nuvem (AWS IMDSv1)',
    targetRoute: '/api/v1/integrations/fetch-webhook',
    httpMethod: 'POST',
    inputPayload: {
      webhookUrl: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
    },
    vulnerabilityTarget: 'axios.get(req.body.webhookUrl)',
    attackVectorType: 'SSRF',
    description: 'Emula chamadas HTTP iniciadas pelo servidor para alvos internos e metadados de instâncias em nuvem sem validação de whitelist de IPs.'
  },
  {
    id: 'scenario-dom',
    name: 'Injeção Dinâmica em eval() via Payload de Perfil',
    targetRoute: '/api/v2/client/load-widget',
    httpMethod: 'POST',
    inputPayload: {
      widgetCode: 'alert(document.cookie); /* malware injected */'
    },
    vulnerabilityTarget: 'eval(payload.widgetCode)',
    attackVectorType: 'DOM XSS',
    description: 'Simula o recebimento de payload dinâmico entregue ao bundle clientPortalBundle.js que executa código JavaScript sem validação estrita.'
  }
];

/**
 * Initial confirmed findings captured through IAST runtime hooks
 */
export const INITIAL_IAST_FINDINGS: IastVulnerabilityFinding[] = [
  {
    id: 'IAST-001',
    title: 'SQL Injection via Interceptação em Runtime na Rota de Usuários',
    cwe: { id: 'CWE-89', name: 'Improper Neutralization of Special Elements used in an SQL Command' },
    owaspCategory: 'A03:2021 - Injection',
    severity: 'CRITICAL',
    confidence: 100,
    status: 'CONFIRMED',
    sourceEndpoint: '/api/v1/users/search',
    httpMethod: 'GET',
    taintedParameter: 'req.query.searchTerm',
    simulatedPayload: "' OR 1=1 --",
    sinkFunction: 'db.query()',
    sinkFile: 'src/controllers/paymentController.js',
    sinkLine: 36,
    vulnerabilityExplanation: 'O hook IAST interceptou a string final enviada ao driver SQL e detectou que a árvore sintática foi alterada dinamicamente: a cláusula WHERE foi neutralizada com sucesso durante a execução em runtime.',
    runtimeEvidence: {
      executedQueryOrCommand: "SELECT id, email, role FROM users WHERE username = 'admin' OR 1=1 --' AND tenant_id = 't-402'",
      unfilteredTaintSubstring: "' OR 1=1 --",
      sanitizerBypassed: 'Nenhum sanitizador ou escape aplicado entre req.query e a consulta SQL',
      runtimeDurationMs: 12.4
    },
    tracePath: [
      {
        stepIndex: 1,
        hookId: 'hook-http-source',
        hookCategory: 'HTTP_REQUEST_SOURCE',
        file: 'src/controllers/paymentController.js',
        line: 29,
        functionName: 'router.get(/api/v1/users/search)',
        variableName: 'req.query.searchTerm',
        runtimeValue: "' OR 1=1 --",
        isTainted: true,
        description: 'Input não confiável recebido via Query String HTTP e marcado com tag Taint:ID#9402.'
      },
      {
        stepIndex: 2,
        hookId: 'hook-fn-propagation',
        hookCategory: 'HTTP_REQUEST_SOURCE',
        file: 'src/services/authService.ts',
        line: 71,
        functionName: 'buildUserQuery(term)',
        variableName: 'sqlBuffer',
        runtimeValue: "SELECT * FROM users WHERE username = '" + "' OR 1=1 --" + "'",
        isTainted: true,
        description: 'Propagação de taint por concatenação de strings direta (+ ou template literal).'
      },
      {
        stepIndex: 3,
        hookId: 'hook-db-sql',
        hookCategory: 'SQL_DATABASE_SINK',
        file: 'src/controllers/paymentController.js',
        line: 36,
        functionName: 'pgClient.query(sqlBuffer)',
        variableName: 'sqlBuffer',
        runtimeValue: "SELECT * FROM users WHERE username = '' OR 1=1 --'",
        isTainted: true,
        description: 'Sink perigoso executado. O sensor IAST confirmou alteração da AST SQL.'
      }
    ],
    runtimeCallStack: [
      'at pgClient.query (node_modules/pg/lib/client.js:142:19)',
      'at buildUserQuery (src/services/authService.ts:71:12)',
      'at /api/v1/users/search handler (src/controllers/paymentController.js:36:5)',
      'at Layer.handle [as handle_request] (node_modules/express/lib/router/layer.js:95:5)'
    ],
    remediationAdvice: 'Utilize consultas parametrizadas (Prepared Statements) fornecidas pelo driver do banco de dados (ex: pg.query("SELECT * FROM users WHERE username = $1", [term])).',
    remediationCodeExample: {
      vulnerable: 'const query = `SELECT * FROM users WHERE username = \'${req.query.searchTerm}\'`;\nawait db.query(query);',
      secure: 'const query = "SELECT * FROM users WHERE username = $1";\nawait db.query(query, [req.query.searchTerm]);'
    }
  },
  {
    id: 'IAST-002',
    title: 'Command Injection Confirmado em Runtime no Subprocesso de Sistema',
    cwe: { id: 'CWE-78', name: 'Improper Neutralization of Special Elements used in an OS Command' },
    owaspCategory: 'A03:2021 - Injection',
    severity: 'CRITICAL',
    confidence: 100,
    status: 'CONFIRMED',
    sourceEndpoint: '/api/v1/diagnostics/ping',
    httpMethod: 'POST',
    taintedParameter: 'req.body.host',
    simulatedPayload: '8.8.8.8; id #',
    sinkFunction: 'child_process.exec()',
    sinkFile: 'src/controllers/paymentController.js',
    sinkLine: 43,
    vulnerabilityExplanation: 'O hook IAST de chamadas de sistema interceptou a chamada exec() e constatou que um comando secundário ("id") seria despachado ao /bin/sh em consequência do caractere delimitador ponto-e-vírgula não sanitizado.',
    runtimeEvidence: {
      executedQueryOrCommand: '/bin/sh -c "ping -c 3 8.8.8.8; id #"',
      unfilteredTaintSubstring: '; id #',
      sanitizerBypassed: 'Nenhuma validação de formato IPv4/FQDN executada',
      runtimeDurationMs: 8.7
    },
    tracePath: [
      {
        stepIndex: 1,
        hookId: 'hook-http-source',
        hookCategory: 'HTTP_REQUEST_SOURCE',
        file: 'src/controllers/paymentController.js',
        line: 41,
        functionName: 'router.post(/api/v1/diagnostics/ping)',
        variableName: 'req.body.host',
        runtimeValue: '8.8.8.8; id #',
        isTainted: true,
        description: 'Parâmetro recebido via POST payload JSON e marcado como taint ativo.'
      },
      {
        stepIndex: 2,
        hookId: 'hook-cmd-exec',
        hookCategory: 'COMMAND_EXEC_SINK',
        file: 'src/controllers/paymentController.js',
        line: 43,
        functionName: 'child_process.exec',
        variableName: 'cmdString',
        runtimeValue: 'ping -c 3 8.8.8.8; id #',
        isTainted: true,
        description: 'Taint propagado sem validação para a invocação da shell sh/bash do sistema operacional.'
      }
    ],
    runtimeCallStack: [
      'at child_process.exec (node:child_process:580:11)',
      'at /api/v1/diagnostics/ping handler (src/controllers/paymentController.js:43:9)',
      'at processTicksAndRejections (node:internal/process/task_queues:95:5)'
    ],
    remediationAdvice: 'Evite child_process.exec(). Se necessário invocar binários, utilize execFile() com array de argumentos estritos e valide o formato de IP com regex ou biblioteca net.isIP().',
    remediationCodeExample: {
      vulnerable: 'child_process.exec(`ping -c 3 ${req.body.host}`);',
      secure: 'if (!net.isIP(req.body.host)) throw new Error("Invalid IP");\nchild_process.execFile("/bin/ping", ["-c", "3", req.body.host]);'
    }
  },
  {
    id: 'IAST-003',
    title: 'Path Traversal Detectado via Hook de Resolução de Arquivo (fs)',
    cwe: { id: 'CWE-22', name: 'Improper Limitation of a Pathname to a Restricted Directory' },
    owaspCategory: 'A01:2021 - Broken Access Control',
    severity: 'HIGH',
    confidence: 95,
    status: 'CONFIRMED',
    sourceEndpoint: '/api/v1/reports/download',
    httpMethod: 'GET',
    taintedParameter: 'req.query.fileName',
    simulatedPayload: '../../../../etc/passwd',
    sinkFunction: 'fs.readFile()',
    sinkFile: 'src/services/secureVaultService.ts',
    sinkLine: 12,
    vulnerabilityExplanation: 'O hook IAST no módulo "fs" avaliou o caminho canônico resultante e constatou que ele quebrou a jaula do diretório seguro (/var/app/reports vs /etc/passwd).',
    runtimeEvidence: {
      executedQueryOrCommand: 'fs.readFile("/etc/passwd")',
      unfilteredTaintSubstring: '../../../../etc/passwd',
      sanitizerBypassed: 'path.join() não impede escape de diretório sem verificação de startsWith()',
      runtimeDurationMs: 4.1
    },
    tracePath: [
      {
        stepIndex: 1,
        hookId: 'hook-http-source',
        hookCategory: 'HTTP_REQUEST_SOURCE',
        file: 'src/services/secureVaultService.ts',
        line: 10,
        functionName: 'downloadReportHandler',
        variableName: 'req.query.fileName',
        runtimeValue: '../../../../etc/passwd',
        isTainted: true,
        description: 'Input com sequências relativas de diretório capturado na requisição.'
      },
      {
        stepIndex: 2,
        hookId: 'hook-path-traversal',
        hookCategory: 'FILE_SYSTEM_TRAVERSAL_SINK',
        file: 'src/services/secureVaultService.ts',
        line: 12,
        functionName: 'fs.readFile',
        variableName: 'resolvedPath',
        runtimeValue: '/etc/passwd',
        isTainted: true,
        description: 'O caminho final aponta para fora da pasta de relatórios permitida.'
      }
    ],
    runtimeCallStack: [
      'at fs.readFile (node:fs:420:10)',
      'at downloadReportHandler (src/services/secureVaultService.ts:12:7)'
    ],
    remediationAdvice: 'Normalize o caminho com path.resolve() e assegure que o resultado inicie estritamente com o diretório base permitido (ex: resolved.startsWith(ALLOWED_DIR)).',
    remediationCodeExample: {
      vulnerable: 'const fullPath = path.join(SAFE_DIR, req.query.fileName);\nfs.readFile(fullPath);',
      secure: 'const safeBase = path.resolve(SAFE_DIR);\nconst fullPath = path.resolve(safeBase, path.basename(req.query.fileName));\nif (!fullPath.startsWith(safeBase)) throw new Error("Acesso não autorizado");'
    }
  },
  {
    id: 'IAST-004',
    title: 'Server-Side Request Forgery (SSRF) Detectado em Runtime',
    cwe: { id: 'CWE-918', name: 'Server-Side Request Forgery (SSRF)' },
    owaspCategory: 'A10:2021 - Server-Side Request Forgery',
    severity: 'HIGH',
    confidence: 98,
    status: 'CONFIRMED',
    sourceEndpoint: '/api/v1/integrations/fetch-webhook',
    httpMethod: 'POST',
    taintedParameter: 'req.body.webhookUrl',
    simulatedPayload: 'http://169.254.169.254/latest/meta-data/',
    sinkFunction: 'axios.get()',
    sinkFile: 'src/services/authService.ts',
    sinkLine: 78,
    vulnerabilityExplanation: 'O sensor de rede de saída interceptou uma tentativa de conexão para o IP de metadados Link-Local 169.254.169.254 com o token do cliente.',
    runtimeEvidence: {
      executedQueryOrCommand: 'axios.get("http://169.254.169.254/latest/meta-data/")',
      unfilteredTaintSubstring: '169.254.169.254',
      sanitizerBypassed: 'Ausência de validação de IP privado ou DNS rebinding guard',
      runtimeDurationMs: 15.3
    },
    tracePath: [
      {
        stepIndex: 1,
        hookId: 'hook-http-source',
        hookCategory: 'HTTP_REQUEST_SOURCE',
        file: 'src/services/authService.ts',
        line: 75,
        functionName: 'dispatchWebhook(url)',
        variableName: 'req.body.webhookUrl',
        runtimeValue: 'http://169.254.169.254/latest/meta-data/',
        isTainted: true,
        description: 'URL fornecida por usuário sem validação de endereço IP.'
      },
      {
        stepIndex: 2,
        hookId: 'hook-ssrf-fetch',
        hookCategory: 'SSRF_NETWORK_SINK',
        file: 'src/services/authService.ts',
        line: 78,
        functionName: 'axios.get',
        variableName: 'targetUrl',
        runtimeValue: 'http://169.254.169.254/latest/meta-data/',
        isTainted: true,
        description: 'Requisição interceptada antes do handshake TCP atingir a VPC ou serviço de metadados.'
      }
    ],
    runtimeCallStack: [
      'at dispatchWebhook (src/services/authService.ts:78:14)',
      'at /api/v1/integrations/fetch-webhook (src/controllers/paymentController.js:46:7)'
    ],
    remediationAdvice: 'Implemente resolução DNS prévia com bloqueio de faixas privadas (RFC 1918, RFC 3927) e bloqueie especificamente o IP de metadados 169.254.169.254.',
    remediationCodeExample: {
      vulnerable: 'await axios.get(req.body.webhookUrl);',
      secure: 'const parsed = new URL(req.body.webhookUrl);\nif (isPrivateOrCloudMetadata(parsed.hostname)) throw new Error("Blocked SSRF Target");\nawait axios.get(parsed.toString());'
    }
  },
  {
    id: 'IAST-005',
    title: 'DOM XSS Dinâmico via Runtime Hook em eval() Client-Side',
    cwe: { id: 'CWE-79', name: 'Improper Neutralization of Input During Web Page Generation' },
    owaspCategory: 'A03:2021 - Injection',
    severity: 'MEDIUM',
    confidence: 90,
    status: 'CONFIRMED',
    sourceEndpoint: '/api/v2/users/profile',
    httpMethod: 'GET',
    taintedParameter: 'res.json().widgetCode',
    simulatedPayload: 'alert(document.domain)',
    sinkFunction: 'window.eval()',
    sinkFile: 'public/static/js/clientPortalBundle.js',
    sinkLine: 139,
    vulnerabilityExplanation: 'O hook do interpretador JavaScript identificou execução dinâmica direta de atributos JSON retornados por API sem checagem de integridade ou sandbox de Web Worker.',
    runtimeEvidence: {
      executedQueryOrCommand: 'eval("alert(document.domain)")',
      unfilteredTaintSubstring: 'alert(document.domain)',
      sanitizerBypassed: 'Nenhum sanitizador DOMPurify aplicado antes de eval()',
      runtimeDurationMs: 1.8
    },
    tracePath: [
      {
        stepIndex: 1,
        hookId: 'hook-http-source',
        hookCategory: 'HTTP_REQUEST_SOURCE',
        file: 'public/static/js/clientPortalBundle.js',
        line: 137,
        functionName: 'loadUserCustomScript(payload)',
        variableName: 'payload.code',
        runtimeValue: 'alert(document.domain)',
        isTainted: true,
        description: 'Objeto de resposta de API transmitido diretamente à função de renderização.'
      },
      {
        stepIndex: 2,
        hookId: 'hook-dom-eval',
        hookCategory: 'DOM_XSS_SINK',
        file: 'public/static/js/clientPortalBundle.js',
        line: 139,
        functionName: 'eval',
        variableName: 'payload.code',
        runtimeValue: 'alert(document.domain)',
        isTainted: true,
        description: 'Execução arbitrária de código interceptada pelo sensor IAST client-side.'
      }
    ],
    runtimeCallStack: [
      'at loadUserCustomScript (public/static/js/clientPortalBundle.js:139:3)',
      'at renderUserProfile (public/static/js/clientPortalBundle.js:171:3)'
    ],
    remediationAdvice: 'Remova totalmente chamadas a eval(). Utilize formatos declarativos estruturados como JSON ou execute em sandboxes isoladas via iframe sem credenciais de sessão.',
    remediationCodeExample: {
      vulnerable: 'eval(payload.code);',
      secure: '// Evite eval inteiramente; consuma dados serializados:\nconst config = JSON.parse(payload.safeData);'
    }
  }
];

/**
 * Executes a simulated runtime emulation run using the workspace files and scenarios
 */
export function runIastRuntimeEmulation(
  files: ScannedFile[],
  activeHooks: IastHookSensor[],
  customScenario?: IastSimulationScenario
): IastExecutionReport {
  const sessionId = 'iast-session-' + Date.now();
  const timestamp = new Date().toLocaleTimeString();

  // If no workspace files, return clean empty report
  if (!files || files.length === 0) {
    return {
      sessionId,
      timestamp,
      status: 'IDLE',
      totalEmulatedRequests: 0,
      totalHooksTriggered: 0,
      findings: [],
      activeHooks,
      coverageMetrics: {
        endpointsInstrumented: 0,
        sinksCovered: 0,
        taintPropagationSuccessRate: 100,
        falsePositiveReductionPercent: 100,
        avgInspectionOverheadMs: 0
      }
    };
  }

  // Filter findings based on active hooks
  const activeHookCategories = new Set(activeHooks.filter(h => h.active).map(h => h.category));
  
  let findings = INITIAL_IAST_FINDINGS.filter(f => {
    return f.tracePath.some(step => activeHookCategories.has(step.hookCategory));
  });

  // If a custom scenario was provided, add or highlight a dynamic finding
  if (customScenario) {
    const dynamicFinding: IastVulnerabilityFinding = {
      id: `IAST-DYN-${Date.now().toString().slice(-4)}`,
      title: `Vulnerabilidade em Runtime: ${customScenario.name}`,
      cwe: {
        id: customScenario.attackVectorType === 'SQLi' ? 'CWE-89' :
            customScenario.attackVectorType === 'Command Injection' ? 'CWE-78' :
            customScenario.attackVectorType === 'Path Traversal' ? 'CWE-22' : 'CWE-918',
        name: `Improper neutralization during dynamic execution of ${customScenario.attackVectorType}`
      },
      owaspCategory: 'A03:2021 - Injection',
      severity: customScenario.attackVectorType === 'SQLi' || customScenario.attackVectorType === 'Command Injection' ? 'CRITICAL' : 'HIGH',
      confidence: 99,
      status: 'CONFIRMED',
      sourceEndpoint: customScenario.targetRoute,
      httpMethod: customScenario.httpMethod,
      taintedParameter: Object.keys(customScenario.inputPayload)[0] || 'input',
      simulatedPayload: String(Object.values(customScenario.inputPayload)[0] || ''),
      sinkFunction: customScenario.vulnerabilityTarget,
      sinkFile: files[0]?.path || 'src/controllers/paymentController.js',
      sinkLine: 35,
      vulnerabilityExplanation: `O hook IAST rastreou o fluxo do payload "${String(Object.values(customScenario.inputPayload)[0])}" durante a emulação de requisição HTTP e comprovou a propagação direta até a chamada do sink sem sanitização.`,
      runtimeEvidence: {
        executedQueryOrCommand: customScenario.vulnerabilityTarget,
        unfilteredTaintSubstring: String(Object.values(customScenario.inputPayload)[0]),
        sanitizerBypassed: 'Nenhum validador de input foi invocado no ciclo de vida da requisição',
        runtimeDurationMs: 14.8
      },
      tracePath: [
        {
          stepIndex: 1,
          hookId: 'hook-http-source',
          hookCategory: 'HTTP_REQUEST_SOURCE',
          file: files[0]?.path || 'src/controllers/paymentController.js',
          line: 25,
          functionName: `handler(${customScenario.targetRoute})`,
          variableName: Object.keys(customScenario.inputPayload)[0] || 'input',
          runtimeValue: String(Object.values(customScenario.inputPayload)[0]),
          isTainted: true,
          description: 'Origem HTTP interceptada e marcada com token de rastreamento de taint.'
        },
        {
          stepIndex: 2,
          hookId: 'hook-target-sink',
          hookCategory: 'SQL_DATABASE_SINK',
          file: files[0]?.path || 'src/controllers/paymentController.js',
          line: 35,
          functionName: customScenario.vulnerabilityTarget.split('(')[0] || 'sink()',
          variableName: 'taintedValue',
          runtimeValue: String(Object.values(customScenario.inputPayload)[0]),
          isTainted: true,
          description: 'Sink perigoso executado com valor tainted.'
        }
      ],
      runtimeCallStack: [
        `at ${customScenario.vulnerabilityTarget.split('(')[0]} (node:internal:100:5)`,
        `at ${customScenario.targetRoute} handler (${files[0]?.path || 'src/controllers/paymentController.js'}:35:10)`
      ],
      remediationAdvice: 'Substitua chamadas dinâmicas por bibliotecas seguras, parâmetros tipados ou validações de esquema rígidas (ex: Zod, Joi).',
      remediationCodeExample: {
        vulnerable: `// Código vulnerável capturado em runtime:\n${customScenario.vulnerabilityTarget};`,
        secure: `// Padrão seguro recomendado:\n// Sanitize e valide antes de processar.`
      }
    };

    findings = [dynamicFinding, ...findings];
  }

  return {
    sessionId,
    timestamp,
    status: 'COMPLETED',
    totalEmulatedRequests: 18 + (customScenario ? 1 : 0),
    totalHooksTriggered: activeHooks.reduce((acc, h) => acc + h.interceptedCallsCount, 0) + 12,
    findings,
    activeHooks,
    coverageMetrics: {
      endpointsInstrumented: 14,
      sinksCovered: activeHooks.length,
      taintPropagationSuccessRate: 98.7,
      falsePositiveReductionPercent: 86.4,
      avgInspectionOverheadMs: 1.4
    }
  };
}
