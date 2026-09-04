import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertOctagon, RotateCcw } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
    };
  }

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error caught by SecScan ErrorBoundary:', error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#050505] text-[#E0E0E0] flex items-center justify-center p-6 font-sans">
          <div className="max-w-lg w-full bg-[#0A0A0A] border border-[#FF3E00]/40 p-8 shadow-2xl space-y-6">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-[#220700] border border-[#FF3E00]/50 flex items-center justify-center text-[#FF3E00]">
                <AlertOctagon className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-black uppercase text-white tracking-tight">
                  SecScan Engine Error
                </h1>
                <p className="text-[11px] font-mono text-[#888]">
                  Ocorreu uma falha na renderização da interface
                </p>
              </div>
            </div>

            <div className="bg-[#050505] border border-[#1F1F1F] p-4 text-xs font-mono text-[#FF7A00] overflow-x-auto max-h-40">
              {this.state.error?.message || 'Erro de execução desconhecido'}
            </div>

            <button
              onClick={this.handleReset}
              className="w-full py-2.5 px-4 bg-[#FF3E00] text-white font-bold uppercase tracking-wider text-xs hover:bg-[#FF551A] transition-colors flex items-center justify-center gap-2 font-mono"
            >
              <RotateCcw className="w-4 h-4" />
              <span>Reiniciar Aplicação</span>
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
