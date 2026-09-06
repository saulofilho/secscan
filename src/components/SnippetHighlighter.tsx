import React, { useState, useMemo } from 'react';
import { Copy, Check, Terminal, ShieldAlert, AlertTriangle, AlertCircle } from 'lucide-react';

interface SnippetHighlighterProps {
  code: string;
  line?: number;
  severity?: 'CRITICAL' | 'HIGH' | 'WARNING';
  className?: string;
}

interface CodeToken {
  type: 'keyword' | 'string' | 'secret-prefix' | 'mask' | 'number' | 'comment' | 'property' | 'operator' | 'punctuation' | 'text';
  text: string;
}

/**
 * Tokenizes code and sensitive pattern previews with special highlighting
 * for security tokens, obfuscated masks, strings, and keywords.
 */
function tokenizePreview(input: string): CodeToken[] {
  const tokens: CodeToken[] = [];
  let remaining = input;

  // Patterns ordered by specificity
  const patterns: Array<{ type: CodeToken['type']; regex: RegExp }> = [
    // Comments
    { type: 'comment', regex: /^(\/\/.*|#.*|\/\*[\s\S]*?\*\/)/ },
    // Sensitive token prefixes
    { 
      type: 'secret-prefix', 
      regex: /^(sk_live_[0-9a-zA-Z]*|rk_live_[0-9a-zA-Z]*|whsec_[0-9a-zA-Z]*|AKIA[0-9A-Z]*|ghp_[0-9a-zA-Z]*|gho_[0-9a-zA-Z]*|github_pat_[0-9a-zA-Z_]*|Bearer\s+|-----BEGIN[ A-Z_-]*-----|-----END[ A-Z_-]*-----|AIza[0-9A-Za-z-_]{35}|xox[baprs]-[0-9a-zA-Z-]*)/i 
    },
    // Mask / Obfuscation indicators
    { type: 'mask', regex: /^(\*{3,}|\.{3,}|•{3,})/ },
    // Strings (double, single, backtick quotes)
    { type: 'string', regex: /^("[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|`[^`\\]*(?:\\.[^`\\]*)*`)/ },
    // Language keywords
    { type: 'keyword', regex: /^(const|let|var|function|return|export|import|from|default|class|interface|type|extends|implements|if|else|switch|case|try|catch|finally|throw|async|await|new|this|typeof|instanceof|void|null|undefined|true|false)\b/ },
    // Variable / Property assignment names
    { type: 'property', regex: /^([a-zA-Z_$][a-zA-Z0-9_$]*)(?=\s*[:=])/ },
    // Numbers (hex, integer, float)
    { type: 'number', regex: /^(0x[0-9a-fA-F]+|\b\d+(\.\d+)?\b)/ },
    // Operators
    { type: 'operator', regex: /^(=>|===|!==|==|!=|<=|>=|&&|\|\||[=+\-*/%:<>!&|^~?])/ },
    // Punctuation
    { type: 'punctuation', regex: /^([{}()[\];,.:])/ },
    // Plain identifiers or whitespace
    { type: 'text', regex: /^([a-zA-Z_$][a-zA-Z0-9_$]*|[ \t]+|\n|[^\s\w])/ }
  ];

  while (remaining.length > 0) {
    let matched = false;
    for (const { type, regex } of patterns) {
      const match = regex.exec(remaining);
      if (match && match[0].length > 0) {
        const text = match[0];

        // If it's a string, check if it contains a secret prefix inside
        if (type === 'string' && (text.includes('sk_') || text.includes('AKIA') || text.includes('ghp_') || text.includes('...') || text.includes('***'))) {
          // Sub-tokenize the string content
          const quote = text[0];
          const inner = text.slice(1, -1);
          tokens.push({ type: 'punctuation', text: quote });
          
          const innerTokens = tokenizePreview(inner);
          tokens.push(...innerTokens);
          
          if (text.length > 1 && text.endsWith(quote)) {
            tokens.push({ type: 'punctuation', text: quote });
          }
        } else {
          tokens.push({ type, text });
        }

        remaining = remaining.slice(text.length);
        matched = true;
        break;
      }
    }

    if (!matched) {
      tokens.push({ type: 'text', text: remaining[0] });
      remaining = remaining.slice(1);
    }
  }

  return tokens;
}

export const SnippetHighlighter: React.FC<SnippetHighlighterProps> = ({
  code,
  line,
  severity = 'CRITICAL',
  className = ''
}) => {
  const [copied, setCopied] = useState(false);

  const tokens = useMemo(() => tokenizePreview(code), [code]);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(code).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1800);
      }).catch(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1800);
      });
    }
  };

  const getSeverityBadge = () => {
    switch (severity) {
      case 'CRITICAL':
        return {
          bg: 'bg-rose-500/15',
          border: 'border-rose-500/30',
          text: 'text-rose-300',
          icon: <ShieldAlert className="w-2.5 h-2.5 text-rose-400" />
        };
      case 'HIGH':
        return {
          bg: 'bg-amber-500/15',
          border: 'border-amber-500/30',
          text: 'text-amber-300',
          icon: <AlertTriangle className="w-2.5 h-2.5 text-amber-400" />
        };
      case 'WARNING':
      default:
        return {
          bg: 'bg-yellow-500/15',
          border: 'border-yellow-500/30',
          text: 'text-yellow-300',
          icon: <AlertCircle className="w-2.5 h-2.5 text-yellow-400" />
        };
    }
  };

  const badge = getSeverityBadge();

  return (
    <div 
      className={`group relative rounded-md bg-[#0a0c10] border border-white/10 overflow-hidden font-mono text-[10.5px] transition-all hover:border-white/20 ${className}`}
    >
      {/* Header bar with line badge and copy button */}
      <div className="flex items-center justify-between px-2 py-0.5 bg-black/60 border-b border-white/10 text-[9.5px]">
        <div className="flex items-center gap-1.5 text-zinc-400">
          <Terminal className="w-2.5 h-2.5 text-zinc-500" />
          <span className="font-semibold uppercase tracking-wider text-[9px] text-zinc-400">Snippet</span>
          {typeof line === 'number' && (
            <span className="px-1 rounded bg-white/10 text-white/80 font-bold">
              L{line}
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5">
          <span className={`inline-flex items-center gap-0.5 px-1 py-0.2 rounded border text-[8.5px] font-bold uppercase tracking-wider ${badge.bg} ${badge.border} ${badge.text}`}>
            {badge.icon}
            <span>Pattern Match</span>
          </span>

          <button
            type="button"
            onClick={handleCopy}
            className="inline-flex items-center gap-1 p-0.5 rounded text-zinc-400 hover:text-white hover:bg-white/10 transition-colors cursor-pointer"
            title="Copiar trecho do padrão detectado"
            aria-label="Copiar código"
          >
            {copied ? (
              <span className="inline-flex items-center gap-0.5 text-emerald-400 text-[8.5px] font-bold">
                <Check className="w-2.5 h-2.5" />
                <span>Copiado</span>
              </span>
            ) : (
              <Copy className="w-2.5 h-2.5 text-zinc-400 hover:text-white" />
            )}
          </button>
        </div>
      </div>

      {/* Highlighted Code Display */}
      <div className="p-2 overflow-x-auto whitespace-pre leading-relaxed scrollbar-thin">
        <code>
          {tokens.map((token, idx) => {
            switch (token.type) {
              case 'secret-prefix':
                return (
                  <span 
                    key={idx} 
                    className="font-bold text-rose-300 bg-rose-950/70 px-1 py-0.5 rounded border border-rose-500/40 shadow-xs"
                    title="Padrão sensível detectado"
                  >
                    {token.text}
                  </span>
                );
              case 'mask':
                return (
                  <span 
                    key={idx} 
                    className="font-black text-amber-400 bg-amber-950/50 px-0.5 rounded tracking-wider"
                    title="Máscara de ofuscação"
                  >
                    {token.text}
                  </span>
                );
              case 'keyword':
                return (
                  <span key={idx} className="text-purple-400 font-semibold">
                    {token.text}
                  </span>
                );
              case 'string':
                return (
                  <span key={idx} className="text-emerald-300">
                    {token.text}
                  </span>
                );
              case 'property':
                return (
                  <span key={idx} className="text-sky-300 font-medium">
                    {token.text}
                  </span>
                );
              case 'number':
                return (
                  <span key={idx} className="text-cyan-300 font-semibold">
                    {token.text}
                  </span>
                );
              case 'comment':
                return (
                  <span key={idx} className="text-zinc-500 italic">
                    {token.text}
                  </span>
                );
              case 'operator':
                return (
                  <span key={idx} className="text-pink-400 font-bold">
                    {token.text}
                  </span>
                );
              case 'punctuation':
                return (
                  <span key={idx} className="text-zinc-400">
                    {token.text}
                  </span>
                );
              case 'text':
              default:
                return (
                  <span key={idx} className="text-zinc-200">
                    {token.text}
                  </span>
                );
            }
          })}
        </code>
      </div>
    </div>
  );
};
