import fs from 'fs';
import path from 'path';
import ts from 'typescript';

const root = process.cwd();
const componentsDir = path.join(root, 'src', 'components');
const testsDir = path.join(componentsDir, '__tests__');

const configFile = ts.readConfigFile(path.join(root, 'tsconfig.json'), ts.sys.readFile);
const parsed = ts.parseJsonConfigFileContent(configFile.config, ts.sys, root);
const program = ts.createProgram(parsed.fileNames, parsed.options);
const checker = program.getTypeChecker();

const preferredLiterals = {
  severity: ['HIGH', 'CRITICAL', 'MEDIUM', 'LOW', 'INFO'],
  activeTab: ['dashboard', 'scanner', 'overview'],
  level: ['HIGH', 'CRITICAL', 'MEDIUM'],
  status: ['OPEN', 'ACTIVE', 'PASSED', 'COMPLIANT'],
  format: ['auto', 'json', 'table'],
  language: ['pt', 'en'],
  riskLevel: ['HIGH', 'CRITICAL', 'MEDIUM'],
  impactLevel: ['HIGH', 'ELEVATED', 'MODERATE'],
  category: ['API_KEY', 'CUSTOM_REGEX', 'PASSWORD'],
};

function preferredLiteral(type, propName) {
  if (!(type.flags & ts.TypeFlags.Union)) return null;
  const literals = type.types.filter((item) => item.isStringLiteral()).map((item) => item.value);
  if (literals.length === 0) return null;
  const preferred = preferredLiterals[propName] ?? [];
  for (const candidate of preferred) {
    if (literals.includes(candidate)) return JSON.stringify(candidate);
  }
  return JSON.stringify(literals[0]);
}

function isArrayType(type) {
  return checker.isArrayType(type) || checker.isTupleType(type);
}

function fixtureFor(type, depth, stack, propName) {
  if (!type || depth > 6) return 'undefined';

  if (type.flags & ts.TypeFlags.Any || type.flags & ts.TypeFlags.Unknown || type.flags & ts.TypeFlags.Never) {
    return propName === 'children' ? `'conteudo'` : 'undefined';
  }
  if (type.flags & ts.TypeFlags.String || type.flags & ts.TypeFlags.StringLiteral) {
    return stringFixture(type, propName);
  }
  if (type.flags & ts.TypeFlags.Number || type.flags & ts.TypeFlags.NumberLiteral) {
    return type.isNumberLiteral() ? String(type.value) : '1';
  }
  if (type.flags & ts.TypeFlags.BooleanLiteral) {
    return checker.typeToString(type);
  }
  if (type.flags & ts.TypeFlags.Boolean) {
    return /^(isOpen|open|visible|show|enabled|active|responsive)$/i.test(propName) ? 'true' : 'false';
  }
  if (type.flags & ts.TypeFlags.Null) return 'null';
  if (type.flags & ts.TypeFlags.Undefined || type.flags & ts.TypeFlags.Void) return 'undefined';
  if (type.flags & ts.TypeFlags.ESSymbol) return 'Symbol.for("unit-test")';

  if (type.flags & ts.TypeFlags.Union || type.flags & ts.TypeFlags.Intersection) {
    const literal = preferredLiteral(type, propName);
    if (literal) return literal;
    const parts = (type.types ?? [type]).filter((item) => !(item.flags & ts.TypeFlags.Undefined) && !(item.flags & ts.TypeFlags.Null));
    const selected = parts[0] ?? type.types?.[0];
    if (!selected || selected === type) return 'undefined';
    return fixtureFor(selected, depth + 1, stack, propName);
  }

  const typeName = checker.typeToString(type);
  if (typeName === 'ReactNode' || typeName === 'React.ReactNode' || typeName.endsWith('.ReactNode')) {
    return `'conteudo'`;
  }
  if (typeName === 'Date') return `new Date('2026-01-15T12:00:00.000Z')`;
  if (typeName.startsWith('Promise<') || typeName === 'Promise<void>') return 'Promise.resolve()';

  if (checker.isTupleType(type)) {
    const elements = checker.getTypeArguments(type);
    return `[${elements.map((item) => fixtureFor(item, depth + 1, stack, propName)).join(', ')}]`;
  }

  if (isArrayType(type)) {
    const element = checker.getElementTypeOfArrayType(type) ?? checker.getIndexTypeOfType(type, ts.IndexKind.Number);
    if (!element) return '[]';
    return `[${fixtureFor(element, depth + 1, stack, propName.replace(/s$/, ''))}]`;
  }

  const callSignatures = type.getCallSignatures();
  if (callSignatures.length > 0 && type.getProperties().every((property) => property.getName() !== 'children')) {
    const returnType = callSignatures[0].getReturnType();
    if (returnType.flags & ts.TypeFlags.Number) return '(..._args) => 1';
    if (returnType.flags & ts.TypeFlags.Boolean) return '(..._args) => false';
    if (returnType.flags & ts.TypeFlags.Void || returnType.flags & ts.TypeFlags.Undefined) return '(..._args) => {}';
    return '(..._args) => "teste"';
  }

  if (stack.has(type.id)) return '{}';
  if (!(type.flags & ts.TypeFlags.Object)) return 'undefined';

  stack.add(type.id);
  try {
    const properties = type.getApparentProperties().filter((property) => {
      const declaration = property.valueDeclaration ?? property.declarations?.[0];
      if (!declaration) return false;
      const fileName = declaration.getSourceFile().fileName;
      return !fileName.includes('node_modules') && !fileName.includes('/typescript/lib/');
    });

    if (properties.length === 0) {
      const indexType = type.getStringIndexType();
      if (indexType) return `{ sample: ${fixtureFor(indexType, depth + 1, stack, 'sample')} }`;
      return '{}';
    }

    const fields = [];
    for (const property of properties) {
      const name = property.getName();
      if (name === 'key' || name === 'ref' || name.startsWith('__')) continue;
      const declaration = property.valueDeclaration ?? property.declarations?.[0];
      const propertyType = checker.getTypeOfSymbolAtLocation(property, declaration);
      const optional = (property.flags & ts.SymbolFlags.Optional) !== 0;
      if (optional && !shouldIncludeOptional(propertyType, depth)) continue;
      const rendered = fixtureFor(propertyType, depth + 1, stack, name);
      if (rendered === 'undefined' && optional) continue;
      const key = /^[A-Za-z_$][\w$]*$/.test(name) ? name : JSON.stringify(name);
      fields.push(`${key}: ${rendered}`);
    }
    return `{ ${fields.join(', ')} }`;
  } finally {
    stack.delete(type.id);
  }
}

function stringFixture(type, propName) {
  if (type.isStringLiteral()) return JSON.stringify(type.value);
  if (/timestamp|createdAt|updatedAt|lastRunAt|date$/i.test(propName)) return `'2026-01-15T12:00:00.000Z'`;
  if (propName === 'children') return `'conteudo'`;
  if (propName === 'className') return `'unit-test'`;
  if (propName === 'activeTab') return `'dashboard'`;
  if (propName === 'severity') return `'HIGH'`;
  if (propName === 'id') return `'unit-test-id'`;
  if (propName === 'file' || propName === 'path') return `'src/unit-test.ts'`;
  if (propName === 'name' || propName === 'title' || propName === 'label') return `'Teste unitário'`;
  if (propName === 'client') return `'ca-pub-1234567890123456'`;
  if (propName === 'slot') return `'1234567890'`;
  return `'teste'`;
}

function shouldIncludeOptional(type, depth) {
  if (depth > 2) return false;
  if (type.flags & (ts.TypeFlags.String | ts.TypeFlags.Number | ts.TypeFlags.Boolean | ts.TypeFlags.StringLiteral | ts.TypeFlags.NumberLiteral | ts.TypeFlags.BooleanLiteral)) {
    return true;
  }
  if (type.flags & ts.TypeFlags.Union) {
    return type.types.every((item) => item.isStringLiteral() || item.isNumberLiteral() || item.flags & ts.TypeFlags.BooleanLiteral || item.flags & ts.TypeFlags.Undefined);
  }
  if (isArrayType(type)) return true;
  if (type.getCallSignatures().length > 0) return true;
  return false;
}

function propsTypeOf(type) {
  const signature = type.getCallSignatures()[0];
  if (signature) {
    const parameter = signature.getParameters()[0];
    if (!parameter) return null;
    const declaration = parameter.valueDeclaration ?? parameter.declarations?.[0];
    if (!declaration) return null;
    return checker.getTypeOfSymbolAtLocation(parameter, declaration);
  }

  const constructor = type.getConstructSignatures()[0];
  if (!constructor) return null;
  const instance = constructor.getReturnType();
  const props = instance.getProperty('props');
  if (!props) return null;
  const declaration = props.valueDeclaration ?? props.declarations?.[0];
  if (!declaration) return null;
  return checker.getTypeOfSymbolAtLocation(props, declaration);
}

function isComponentType(name, type) {
  if (!/^[A-Z]/.test(name)) return false;
  if (type.getCallSignatures().length > 0) return true;
  return type.getConstructSignatures().some((signature) => signature.getReturnType().getProperty('render'));
}

function componentExports(sourceFile) {
  const moduleSymbol = checker.getSymbolAtLocation(sourceFile);
  if (!moduleSymbol) return [];
  return checker.getExportsOfModule(moduleSymbol).flatMap((symbol) => {
    if (!(symbol.flags & ts.SymbolFlags.Value) || symbol.getName() === '__exportStar') return [];
    const declaration = symbol.valueDeclaration ?? symbol.declarations?.[0];
    if (!declaration) return [];
    const type = checker.getTypeOfSymbolAtLocation(symbol, declaration);
    const exportName = symbol.getName();
    if (!isComponentType(exportName === 'default' ? 'DefaultExport' : exportName, type)) return [];
    return [{ exportName, type, localName: exportName === 'default' ? 'ComponentDefault' : exportName }];
  });
}

function extraTests(component) {
  if (component.localName === 'ErrorBoundary') {
    return `
  it('mostra a falha de renderização capturada', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const Bomb = () => {
      throw new Error('render-boundary-error');
    };
    const view = renderWithProviders(
      <ErrorBoundary>
        <Bomb />
      </ErrorBoundary>
    );
    expect(view.container).toHaveTextContent('SecScan Engine Error');
    expect(view.container).toHaveTextContent('render-boundary-error');
    view.unmount();
    spy.mockRestore();
  });
`;
  }

  if (component.localName === 'GoogleAdBanner') {
    return `
  it('não renderiza o anúncio sem credenciais', () => {
    const view = renderWithProviders(<GoogleAdBanner />);
    expect(view.container.querySelector('ins.adsbygoogle')).toBeNull();
    view.unmount();
  });

  it('renderiza o slot quando cliente e bloco são informados', () => {
    const view = renderWithProviders(
      <GoogleAdBanner client="ca-pub-1234567890123456" slot="1234567890" />
    );
    const slot = view.container.querySelector('ins.adsbygoogle');
    expect(slot).not.toBeNull();
    expect(slot?.getAttribute('data-ad-client')).toBe('ca-pub-1234567890123456');
    expect(slot?.getAttribute('data-ad-slot')).toBe('1234567890');
    view.unmount();
  });

  it('inicializa um novo slot ao reativar a exibição', () => {
    const view = renderWithProviders(
      <GoogleAdBanner client="ca-pub-1234567890123456" slot="1234567890" />
    );
    const pushesAntes = window.adsbygoogle?.length ?? 0;
    act(() => {
      window.dispatchEvent(new CustomEvent('secscan_ad_mode_changed', { detail: { adFree: true } }));
    });
    expect(view.container.querySelector('ins.adsbygoogle')).toBeNull();
    act(() => {
      window.dispatchEvent(new CustomEvent('secscan_ad_mode_changed', { detail: { adFree: false } }));
    });
    expect(view.container.querySelector('ins.adsbygoogle')).not.toBeNull();
    expect(window.adsbygoogle?.length ?? 0).toBeGreaterThan(pushesAntes);
    view.unmount();
  });
`;
  }

  return '';
}

fs.mkdirSync(testsDir, { recursive: true });

const files = fs.readdirSync(componentsDir).filter((file) => file.endsWith('.tsx')).sort();
let componentCount = 0;
const missed = [];

for (const file of files) {
  const sourceFile = program.getSourceFile(path.join(componentsDir, file));
  if (!sourceFile) {
    missed.push(`${file} (arquivo ausente no programa TypeScript)`);
    continue;
  }
  const components = componentExports(sourceFile);
  if (components.length === 0) {
    missed.push(file);
    continue;
  }

  const named = components.filter((component) => component.exportName !== 'default');
  const defaults = components.filter((component) => component.exportName === 'default');
  const importNames = named.map((component) => component.localName).join(', ');
  const importLine = [
    defaults.length ? `import ComponentDefault${importNames ? `, { ${importNames} }` : ''} from '../${file.replace(/\.tsx$/, '')}';` : '',
    !defaults.length && importNames ? `import { ${importNames} } from '../${file.replace(/\.tsx$/, '')}';` : '',
  ].filter(Boolean)[0];

  const needsAct = components.some((component) => component.localName === 'GoogleAdBanner');
  const needsVi = components.some((component) => component.localName === 'ErrorBoundary');
  const vitestImports = ['describe', 'expect', 'it', needsVi ? 'vi' : ''].filter(Boolean).join(', ');
  const testingImports = needsAct ? `import { act } from '@testing-library/react';\n` : '';

  const blocks = components.map((component) => {
    const propsType = propsTypeOf(component.type);
    const props = propsType ? fixtureFor(propsType, 0, new Set(), 'props') : '{}';
    componentCount += 1;
    return `  it('monta ${component.localName} com as props do contrato', () => {
    const view = renderWithProviders(<${component.localName} {...(${props} as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
${extraTests(component)}`;
  }).join('\n');

  const baseName = file.replace(/\.tsx$/, '');
  const contents = `import { ${vitestImports} } from 'vitest';
${testingImports}import { renderWithProviders } from '../../test/renderWithProviders';
${importLine}

describe('${baseName}', () => {
${blocks}});
`;
  fs.writeFileSync(path.join(testsDir, `${baseName}.test.tsx`), contents);
}

console.log(`Componentes cobertos: ${componentCount}`);
console.log(`Arquivos sem componente exportado: ${missed.length}`);
if (missed.length) console.log(missed.join('\n'));
