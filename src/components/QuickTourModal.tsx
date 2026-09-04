import React, { useState } from 'react';
import { 
  Compass, 
  X, 
  ChevronRight, 
  ChevronLeft, 
  Upload, 
  Search, 
  ShieldAlert, 
  FolderTree, 
  Terminal, 
  Download, 
  Check, 
  Sparkles,
  ExternalLink,
  Code2
} from 'lucide-react';

interface QuickTourModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateToTab: (tab: string) => void;
}

interface TourStep {
  stepNumber: number;
  badge: string;
  title: string;
  targetTab?: string;
  description: string;
  keyPoints: { icon: any; title: string; text: string }[];
  actionLabel?: string;
  actionTab?: string;
}

export const QuickTourModal: React.FC<QuickTourModalProps> = ({
  isOpen,
  onClose,
  onNavigateToTab
}) => {
  const [currentStep, setCurrentStep] = useState(0);

  if (!isOpen) return null;

  const tourSteps: TourStep[] = [
    {
      stepNumber: 1,
      badge: '01 // INTRODUÇÃO & ARQUITETURA',
      title: 'Bem-vindo ao SecScan SAST',
      targetTab: 'dashboard',
      description: 'O SecScan é um motor de análise estática de segurança (SAST) voltado para JavaScript e TypeScript. Ele analisa códigos em tempo real, calculando a entropia de Shannon e aplicando regras de segurança OWASP.',
      keyPoints: [
        {
          icon: ShieldAlert,
          title: 'Detecção em Tempo Real',
          text: 'O código é varrido linha a linha buscando tokens JWT, chaves de API, credenciais AWS e segredos de alta entropia.'
        },
        {
          icon: FolderTree,
          title: 'Filtro Zero-Dependency',
          text: 'Pastas como node_modules/** e dist/** são ignoradas automaticamente, focando 100% no código proprietário da aplicação.'
        },
        {
          icon: Sparkles,
          title: 'Dados de Exemplo Pré-Carregados',
          text: 'A aplicação já vem com um repositório realista (paymentController, authService, etc.) para você testar imediatamente.'
        }
      ],
      actionLabel: 'Ver Métricas no Dashboard',
      actionTab: 'dashboard'
    },
    {
      stepNumber: 2,
      badge: '02 // ONDE ENCONTRAR OS ACHADOS (FINDINGS)',
      title: 'Localizando Vulnerabilidades e Hotspots',
      targetTab: 'dashboard',
      description: 'Você pode inspecionar os achados em 3 níveis de profundidade conforme a necessidade da sua equipe técnica:',
      keyPoints: [
        {
          icon: Search,
          title: 'D3 Density Heatmap',
          text: 'Localizado no Dashboard, mostra exatamente quais diretórios ou arquivos concentram o maior número de alertas críticos.'
        },
        {
          icon: Code2,
          title: 'Inspetor de Código Linha a Linha',
          text: 'Na aba "Inspetor de Código", clique em qualquer arquivo para ver as linhas destacadas em vermelho, o cálculo de entropia e a regra violada.'
        },
        {
          icon: Sparkles,
          title: 'Sugestão de Remediação Segura',
          text: 'Cada achado gera automaticamente um snippet corrigido usando process.env.<NOME_VARIAVEL> para remover senhas hardcoded.'
        }
      ],
      actionLabel: 'Abrir Inspetor de Código',
      actionTab: 'scanner'
    },
    {
      stepNumber: 3,
      badge: '03 // COMO SUBMETER SEU PRÓPRIO CÓDIGO',
      title: 'Carregando Seus Arquivos para Varredura',
      targetTab: 'scanner',
      description: 'Você não precisa ficar restrito aos arquivos de exemplo. Existem 3 maneiras rápidas de analisar seu código real:',
      keyPoints: [
        {
          icon: Upload,
          title: 'Arrastar e Soltar (Drag & Drop)',
          text: 'Na barra lateral da aba "Inspetor de Código", solte seus arquivos (.js, .ts, .env, .json) na caixa de upload.'
        },
        {
          icon: Code2,
          title: 'Colar Código Diretamente ("Paste Code")',
          text: 'Clique no botão "Paste Code" no Inspetor para colar qualquer snippet do seu repositório e analisá-lo instantaneamente.'
        },
        {
          icon: Terminal,
          title: 'Executar via Terminal CLI',
          text: 'Use a aba "Terminal CLI" e digite "secscan run ." para disparar uma auditoria completa pelo console interativo.'
        }
      ],
      actionLabel: 'Ir para Área de Upload',
      actionTab: 'scanner'
    },
    {
      stepNumber: 4,
      badge: '04 // EXPORTAÇÃO, CI/CD E NUVEM',
      title: 'Pipelines e Automação DevSecOps',
      targetTab: 'cicd',
      description: 'Integre o SecScan ao fluxo de trabalho do seu time com exportações padronizadas e automação de segredos:',
      keyPoints: [
        {
          icon: Download,
          title: 'Exportação SARIF 2.1.0 e JSON',
          text: 'Exporte o relatório no formato padrão SARIF para exibir os alertas nativamente na aba Security do GitHub.'
        },
        {
          icon: Terminal,
          title: 'Workflow do GitHub Actions',
          text: 'Acesse a aba "CI/CD & Cloud" para copiar o template de pipeline pronto para quebrar builds em caso de vazamentos.'
        },
        {
          icon: FolderTree,
          title: 'KMS & Cloud Secret Manager',
          text: 'Veja exemplos de integração com AWS Secrets Manager e Google Cloud Secret Manager para eliminar variáveis estáticas.'
        }
      ],
      actionLabel: 'Ver Pipeline CI/CD',
      actionTab: 'cicd'
    }
  ];

  const current = tourSteps[currentStep];

  const handleNext = () => {
    if (currentStep < tourSteps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      onClose();
    }
  };

  const handlePrev = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleActionClick = (tab?: string) => {
    if (tab) {
      onNavigateToTab(tab);
    }
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-md flex items-center justify-center p-4">
      <div className="bg-[#0A0A0A] max-w-2xl w-full border border-[#333] shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="p-6 bg-[#0D0D0D] border-b border-[#222] flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="text-[10px] font-black tracking-[0.25em] text-[#FF3E00] uppercase">
                {current.badge}
              </span>
              <span className="text-[9px] font-mono px-2 py-0.5 bg-[#141414] text-[#AAA] border border-[#262626]">
                PASSO {currentStep + 1} DE {tourSteps.length}
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white mt-1.5 flex items-center gap-2.5">
              <Compass className="w-5 h-5 text-[#FF3E00]" />
              <span>{current.title}</span>
            </h2>
          </div>
          <button 
            onClick={onClose}
            className="text-[#666] hover:text-white p-1 transition-colors"
            title="Fechar Guia"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 sm:p-8 space-y-6 overflow-y-auto max-h-[65vh]">
          <p className="text-xs font-mono text-[#AAA] leading-relaxed">
            {current.description}
          </p>

          {/* Key Points Grid */}
          <div className="space-y-3">
            {current.keyPoints.map((point, idx) => {
              const Icon = point.icon;
              return (
                <div 
                  key={idx}
                  className="bg-[#050505] p-4 border border-[#1A1A1A] hover:border-[#333] transition-colors flex items-start gap-3.5"
                >
                  <div className="w-8 h-8 bg-[#111] border border-[#262626] flex items-center justify-center shrink-0 text-[#FF3E00] mt-0.5">
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="space-y-1">
                    <h3 className="text-xs font-black uppercase tracking-wider text-white">
                      {point.title}
                    </h3>
                    <p className="text-[11px] font-mono text-[#888] leading-relaxed">
                      {point.text}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Step Action Button */}
          {current.actionLabel && (
            <div className="bg-[#111] p-3.5 border border-[#222] flex items-center justify-between">
              <span className="text-[11px] font-mono text-[#888]">
                Deseja pular direto para esta seção agora?
              </span>
              <button
                onClick={() => handleActionClick(current.actionTab)}
                className="px-3 py-1.5 text-[10px] font-black uppercase tracking-wider bg-white text-black hover:bg-[#FF3E00] hover:text-white transition-colors flex items-center gap-1.5"
              >
                <span>{current.actionLabel}</span>
                <ExternalLink className="w-3 h-3" />
              </button>
            </div>
          )}
        </div>

        {/* Footer Navigation */}
        <div className="p-4 sm:p-6 bg-[#080808] border-t border-[#1F1F1F] flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            {tourSteps.map((_, idx) => (
              <button
                key={idx}
                onClick={() => setCurrentStep(idx)}
                className={`h-2 transition-all ${
                  idx === currentStep 
                    ? 'w-6 bg-[#FF3E00]' 
                    : 'w-2 bg-[#222] hover:bg-[#444]'
                }`}
                title={`Ir para passo ${idx + 1}`}
              />
            ))}
          </div>

          <div className="flex items-center gap-2.5">
            {currentStep > 0 && (
              <button
                onClick={handlePrev}
                className="px-4 py-2 text-[10px] font-black uppercase tracking-wider text-white bg-[#111] hover:bg-[#222] border border-[#333] transition-colors flex items-center gap-1.5"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
                <span>Anterior</span>
              </button>
            )}

            <button
              onClick={handleNext}
              className="px-5 py-2 text-[10px] font-black uppercase tracking-wider text-black bg-white hover:bg-[#FF3E00] hover:text-white transition-colors flex items-center gap-1.5 font-mono"
            >
              <span>{currentStep === tourSteps.length - 1 ? 'Concluir Tour' : 'Próximo'}</span>
              {currentStep === tourSteps.length - 1 ? (
                <Check className="w-3.5 h-3.5" />
              ) : (
                <ChevronRight className="w-3.5 h-3.5" />
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
