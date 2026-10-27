import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { SnippetHighlighter } from '../SnippetHighlighter';

describe('SnippetHighlighter', () => {
  it('monta SnippetHighlighter com as props do contrato', () => {
    const view = renderWithProviders(<SnippetHighlighter {...({ code: 'teste', line: 1, severity: "HIGH", className: 'unit-test' } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
