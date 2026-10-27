import { describe, expect, it } from 'vitest';
import { ScannedFile } from '../types';
import { enrichScaReportWithOsv, scanSoftwareCompositionAnalysis } from './scaScanner';

const manifest: ScannedFile = {
  name: 'package.json',
  path: 'package.json',
  size: 80,
  extension: 'json',
  content: JSON.stringify({
    dependencies: {
      lodash: '4.17.15',
      'left-pad': '1.0.0'
    }
  })
};

describe('SCA', () => {
  it('mantém pacote fora do catálogo local como NOT_IN_CATALOG', () => {
    const report = scanSoftwareCompositionAnalysis([manifest]);
    const leftPad = report.packages.find((pkg) => pkg.name === 'left-pad');
    const lodash = report.packages.find((pkg) => pkg.name === 'lodash');
    expect(leftPad?.license).toBe('NOT_IN_CATALOG');
    expect(leftPad?.vulnerabilities).toEqual([]);
    expect(lodash?.vulnerabilities.some((vuln) => vuln.cveId === 'CVE-2020-8203')).toBe(true);
    expect(report.catalogMode).toBe('CURATED_LOCAL');
    expect(report.osvStatus).toBe('NOT_QUERIED');
  });

  it('soma advisory do OSV sem duplicar o CVE local', async () => {
    const local = scanSoftwareCompositionAnalysis([manifest]);
    const fetchImpl = async () => new Response(JSON.stringify({
      results: [
        {
          vulns: [
            { id: 'CVE-2020-8203', summary: 'já está no catálogo' },
            { id: 'GHSA-new-osv-only', summary: 'advisory só no OSV', database_specific: { severity: 'HIGH' } }
          ]
        },
        { vulns: [] }
      ]
    }), { status: 200, headers: { 'content-type': 'application/json' } });

    const enriched = await enrichScaReportWithOsv(local, fetchImpl);
    const lodash = enriched.packages.find((pkg) => pkg.name === 'lodash');
    expect(enriched.catalogMode).toBe('OSV');
    expect(enriched.osvStatus).toBe('OK');
    expect(lodash?.vulnerabilities.filter((vuln) => vuln.cveId === 'CVE-2020-8203')).toHaveLength(1);
    expect(lodash?.vulnerabilities.some((vuln) => vuln.ghsaId === 'GHSA-new-osv-only')).toBe(true);
    expect(lodash?.license).not.toBe('NOT_IN_CATALOG');
  });

  it('permanece no catálogo local quando o OSV não responde JSON', async () => {
    const local = scanSoftwareCompositionAnalysis([manifest]);
    const fetchImpl = async () => new Response('<html></html>', { status: 200, headers: { 'content-type': 'text/html' } });
    const enriched = await enrichScaReportWithOsv(local, fetchImpl);
    expect(enriched.catalogMode).toBe('CURATED_LOCAL');
    expect(enriched.osvStatus).toBe('UNREACHABLE');
    expect(enriched.allVulnerabilities).toEqual(local.allVulnerabilities);
  });
});
