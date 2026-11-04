import { describe, expect, it } from 'vitest';
import { FEATURE_REGISTRY } from './featureRegistry';
import { CONSOLE_MODULES, runConsoleModule } from './consoleWorkspace';

describe('console workspace', () => {
  it('covers every module in the app hub', () => {
    const ids = new Set(CONSOLE_MODULES.map((module) => module.id));
    const missing = FEATURE_REGISTRY.map((feature) => feature.id).filter((id) => !ids.has(id));
    expect(missing).toEqual([]);
  });

  it('prints the laboratory banner for nmap and does not claim a live scan', () => {
    const result = runConsoleModule('nmap', { target: '.', files: [], findings: [] });
    expect(result.lines[0]).toContain('Laboratório');
    expect(result.lines.join('\n')).not.toContain('nmap ');
  });
});
