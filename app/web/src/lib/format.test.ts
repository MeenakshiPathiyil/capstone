import { describe, expect, it } from 'vitest'

import {
  attackTechniqueUrl,
  chainText,
  fileExtension,
  formatBytes,
  formatCount,
  formatDateTime,
  formatDuration,
  formatFactor,
  formatPercent,
  formatResourceType,
  formatScore,
  identifierBreaks,
  safeHttpUrl,
  pluralize,
  sentenceCase,
  splitSampleDescription,
  shortHash,
} from './format'

describe('formatCount', () => {
  it('groups thousands', () => {
    expect(formatCount(0)).toBe('0')
    expect(formatCount(22)).toBe('22')
    expect(formatCount(1234567)).toBe('1,234,567')
  })
})

describe('formatScore', () => {
  it('always shows two decimals, like the backend rounding', () => {
    expect(formatScore(56.04)).toBe('56.04')
    expect(formatScore(30)).toBe('30.00')
    expect(formatScore(28.9)).toBe('28.90')
  })

  it('shows a hyphen for a missing score', () => {
    expect(formatScore(null)).toBe('-')
    expect(formatScore(undefined)).toBe('-')
    expect(formatScore(Number.NaN)).toBe('-')
  })
})

describe('formatFactor and formatPercent', () => {
  it('trims multipliers to three places without trailing zeros', () => {
    expect(formatFactor(0.85 ** 3)).toBe('0.614')
    expect(formatFactor(1.25)).toBe('1.25')
    expect(formatFactor(1)).toBe('1')
  })

  it('rounds fractions to whole percents', () => {
    expect(formatPercent(0.4)).toBe('40%')
    expect(formatPercent(19 / 22)).toBe('86%')
  })
})

describe('formatBytes', () => {
  it('uses binary units with at most one decimal under 10', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(1023)).toBe('1023 B')
    expect(formatBytes(1536)).toBe('1.5 KB')
    expect(formatBytes(2 * 1024 * 1024)).toBe('2 MB')
    expect(formatBytes(2 * 1024 * 1024 + 1)).toBe('2 MB')
    expect(formatBytes(15 * 1024 * 1024)).toBe('15 MB')
  })

  it('shows a hyphen for impossible sizes', () => {
    expect(formatBytes(-1)).toBe('-')
    expect(formatBytes(Number.POSITIVE_INFINITY)).toBe('-')
  })
})

describe('pluralize', () => {
  it('picks the singular only for exactly one', () => {
    expect(pluralize(1, 'finding')).toBe('1 finding')
    expect(pluralize(0, 'finding')).toBe('0 findings')
    expect(pluralize(1200, 'path')).toBe('1,200 paths')
    expect(pluralize(2, 'hop', 'hops')).toBe('2 hops')
  })
})

describe('formatDuration', () => {
  it('scales from tenths of a second to minutes', () => {
    expect(formatDuration(0.24)).toBe('0.2 s')
    expect(formatDuration(9.96)).toBe('10 s')
    expect(formatDuration(42.4)).toBe('42 s')
    expect(formatDuration(120)).toBe('2 min')
    expect(formatDuration(125)).toBe('2 min 5 s')
  })

  it('shows a hyphen for missing or negative values', () => {
    expect(formatDuration(null)).toBe('-')
    expect(formatDuration(-3)).toBe('-')
  })
})

describe('formatDateTime', () => {
  it('formats a UTC ISO timestamp the same on every machine', () => {
    expect(formatDateTime('2026-10-24T10:28:00Z')).toBe('24 Oct 2026, 10:28 UTC')
    expect(formatDateTime('2026-01-05T23:59:59+00:00')).toBe('5 Jan 2026, 23:59 UTC')
  })

  it('shows a hyphen for missing or unparseable input', () => {
    expect(formatDateTime(null)).toBe('-')
    expect(formatDateTime('not a date')).toBe('-')
  })
})

describe('identifiers', () => {
  it('shortens hashes', () => {
    expect(shortHash('9c1f2ab7d3e4f5a6b7c8')).toBe('9c1f2ab')
    expect(shortHash('9c1f2ab7d3e4f5a6b7c8', 12)).toBe('9c1f2ab7d3e4')
  })

  it('drops the AWS prefix from resource types and leaves others alone', () => {
    expect(formatResourceType('AWS::EC2::SecurityGroup')).toBe('EC2 SecurityGroup')
    expect(formatResourceType('AWS::IAM::Role')).toBe('IAM Role')
    expect(formatResourceType('AWS::ElasticLoadBalancingV2::LoadBalancer')).toBe(
      'ELBv2 LoadBalancer',
    )
    expect(formatResourceType('AWS::ElasticLoadBalancing::LoadBalancer')).toBe('ELB LoadBalancer')
    expect(formatResourceType('Custom::AuditHook')).toBe('Custom::AuditHook')
    expect(formatResourceType('AWS::Serverless::Function::Extra')).toBe(
      'AWS::Serverless::Function::Extra',
    )
  })

  it('joins hops with arrows', () => {
    expect(chainText(['OpenSecurityGroup', 'PublicEC2Instance', 'InsecureS3Bucket'])).toBe(
      'OpenSecurityGroup → PublicEC2Instance → InsecureS3Bucket',
    )
    expect(chainText([])).toBe('')
  })
})

describe('identifierBreaks', () => {
  it('splits CamelCase and separators without losing characters', () => {
    expect(identifierBreaks('OverPermissiveRole')).toEqual(['Over', 'Permissive', 'Role'])
    expect(identifierBreaks('PublicEC2Instance')).toEqual(['Public', 'EC2', 'Instance'])
    expect(identifierBreaks('Custom::AuditHook')).toEqual(['Custom::', 'Audit', 'Hook'])
    expect(identifierBreaks('my-bucket_name.v2')).toEqual(['my-', 'bucket_', 'name.', 'v2'])
    expect(identifierBreaks('lower')).toEqual(['lower'])
    expect(identifierBreaks('')).toEqual([])
    const id = 'PaymentsServiceExecutionRoleWithWildcardPassRole'
    expect(identifierBreaks(id).join('')).toBe(id)
  })
})

describe('splitSampleDescription', () => {
  it('separates a leading template path from the sentence', () => {
    expect(
      splitSampleDescription(
        'sample_yamls/cloudformation5.yml: public load balancer and a database.',
      ),
    ).toEqual({
      file: 'sample_yamls/cloudformation5.yml',
      text: 'Public load balancer and a database.',
    })
  })

  it('leaves descriptions without a file prefix alone', () => {
    expect(splitSampleDescription('A small stack: two buckets.')).toEqual({
      file: null,
      text: 'A small stack: two buckets.',
    })
  })
})

describe('attackTechniqueUrl', () => {
  it('links techniques and sub-techniques', () => {
    expect(attackTechniqueUrl('T1190')).toBe('https://attack.mitre.org/techniques/T1190/')
    expect(attackTechniqueUrl('T1552.005')).toBe('https://attack.mitre.org/techniques/T1552/005/')
  })

  it('returns null for anything that is not a technique id, so no broken link is drawn', () => {
    expect(attackTechniqueUrl(null)).toBeNull()
    expect(attackTechniqueUrl('')).toBeNull()
    expect(attackTechniqueUrl('TA0001')).toBeNull()
    expect(attackTechniqueUrl('T1190 - Exploit')).toBeNull()
  })
})

describe('sentenceCase', () => {
  it('turns snake case and lower case into a sentence', () => {
    expect(sentenceCase('network_control')).toBe('Network control')
    expect(sentenceCase('initial access')).toBe('Initial access')
    expect(sentenceCase('DATA_THEFT')).toBe('Data theft')
    expect(sentenceCase('')).toBe('')
  })
})

describe('fileExtension', () => {
  it('lower-cases the last extension and ignores dotfiles', () => {
    expect(fileExtension('stack.YAML')).toBe('.yaml')
    expect(fileExtension('parent.nested.template')).toBe('.template')
    expect(fileExtension('README')).toBe('')
    expect(fileExtension('.yaml')).toBe('')
  })
})

describe('safeHttpUrl', () => {
  it('returns absolute http and https URLs and nothing else', () => {
    expect(safeHttpUrl('https://docs.aws.amazon.com/config/latest/developerguide/x.html')).toBe(
      'https://docs.aws.amazon.com/config/latest/developerguide/x.html',
    )
    expect(safeHttpUrl('http://example.com/a?b=c')).toBe('http://example.com/a?b=c')
    expect(safeHttpUrl('javascript:alert(1)')).toBeNull()
    expect(safeHttpUrl('data:text/html,<b>x</b>')).toBeNull()
    expect(safeHttpUrl('ftp://example.com/x')).toBeNull()
    expect(safeHttpUrl('/relative/path')).toBeNull()
    expect(safeHttpUrl('')).toBeNull()
    expect(safeHttpUrl(null)).toBeNull()
    expect(safeHttpUrl(undefined)).toBeNull()
  })
})
