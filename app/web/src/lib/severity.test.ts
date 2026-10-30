import { describe, expect, it } from 'vitest'

import {
  applySeverityPalette,
  compareLevel,
  compareSeverity,
  contrastRatio,
  countBySeverity,
  DEFAULT_SEVERITY_STYLES,
  isAttackLevel,
  isSeverity,
  isTone,
  levelLabel,
  levelTone,
  maxSeverity,
  meetsLevel,
  resourceTone,
  severityLabel,
  severityVar,
  TONES,
  type AttackLevel,
  type Severity,
} from './severity'

describe('ordering', () => {
  it('sorts severities most severe first', () => {
    const sorted: Severity[] = ['low', 'unknown', 'critical', 'medium', 'high']
    sorted.sort(compareSeverity)
    expect(sorted).toEqual(['critical', 'high', 'medium', 'low', 'unknown'])
  })

  it('sorts levels most severe first', () => {
    const sorted: AttackLevel[] = ['MEDIUM', 'CRITICAL', 'HIGH']
    sorted.sort(compareLevel)
    expect(sorted).toEqual(['CRITICAL', 'HIGH', 'MEDIUM'])
  })

  it('finds the most severe, or null for none', () => {
    expect(maxSeverity(['low', 'high', 'medium'])).toBe('high')
    expect(maxSeverity(['unknown', 'low'])).toBe('low')
    expect(maxSeverity([])).toBeNull()
  })

  it('applies the minimum level the way the backend selects paths', () => {
    expect(meetsLevel('CRITICAL', 'HIGH')).toBe(true)
    expect(meetsLevel('HIGH', 'HIGH')).toBe(true)
    expect(meetsLevel('MEDIUM', 'HIGH')).toBe(false)
    expect(meetsLevel('MEDIUM', 'MEDIUM')).toBe(true)
    expect(meetsLevel('HIGH', 'CRITICAL')).toBe(false)
  })
})

describe('labels and tones', () => {
  it('maps attack levels onto severity tones', () => {
    expect(levelTone('CRITICAL')).toBe('critical')
    expect(levelTone('HIGH')).toBe('high')
    expect(levelTone('MEDIUM')).toBe('medium')
  })

  it('draws a resource without findings as clean', () => {
    expect(resourceTone(null)).toBe('clean')
    expect(resourceTone(undefined)).toBe('clean')
    expect(resourceTone('critical')).toBe('critical')
  })

  it('labels in sentence case', () => {
    expect(severityLabel('critical')).toBe('Critical')
    expect(severityLabel('clean')).toBe('No findings')
    expect(levelLabel('HIGH')).toBe('High')
  })

  it('guards unknown strings', () => {
    expect(isSeverity('high')).toBe(true)
    expect(isSeverity('clean')).toBe(false)
    expect(isSeverity('HIGH')).toBe(false)
    expect(isTone('clean')).toBe(true)
    expect(isTone(undefined)).toBe(false)
    expect(isAttackLevel('HIGH')).toBe(true)
    expect(isAttackLevel('LOW')).toBe(false)
  })
})

describe('countBySeverity', () => {
  it('counts in display order and keeps zeros', () => {
    expect(countBySeverity(['high', 'critical', 'high', 'low'])).toEqual([
      { severity: 'critical', count: 1 },
      { severity: 'high', count: 2 },
      { severity: 'medium', count: 0 },
      { severity: 'low', count: 1 },
      { severity: 'unknown', count: 0 },
    ])
  })
})

describe('applySeverityPalette', () => {
  it('writes fill and stroke variables for every known tone', () => {
    const target = document.createElement('div')
    const applied = applySeverityPalette(DEFAULT_SEVERITY_STYLES, target)
    expect(applied).toEqual([...TONES])
    expect(target.style.getPropertyValue('--sev-critical-fill')).toBe('#f8b4b4')
    expect(target.style.getPropertyValue('--sev-unknown-stroke')).toBe('#4c1d95')
    expect(severityVar('low', 'fill')).toBe('--sev-low-fill')
  })

  it('ignores unknown keys and values that are not hex colours', () => {
    const target = document.createElement('div')
    const applied = applySeverityPalette(
      {
        critical: { fill: '#ff0000', stroke: '#330000' },
        high: { fill: 'red; background: url(x)', stroke: '#000' },
        severe: { fill: '#123456', stroke: '#654321' },
      },
      target,
    )
    expect(applied).toEqual(['critical'])
    expect(target.style.getPropertyValue('--sev-critical-fill')).toBe('#ff0000')
    expect(target.style.getPropertyValue('--sev-high-fill')).toBe('')
    expect(target.style.getPropertyValue('--sev-severe-fill')).toBe('')
  })
})

describe('contrast', () => {
  it('matches the WCAG reference values', () => {
    expect(contrastRatio('#000000', '#ffffff')).toBeCloseTo(21, 5)
    expect(contrastRatio('#ffffff', '#ffffff')).toBeCloseTo(1, 5)
    expect(contrastRatio('#777', '#fff')).toBeCloseTo(4.48, 2)
  })

  it('passes AA for stroke text on every fill in the shipped palette', () => {
    for (const tone of TONES) {
      const { fill, stroke } = DEFAULT_SEVERITY_STYLES[tone]
      expect(contrastRatio(stroke, fill), tone).toBeGreaterThanOrEqual(4.5)
    }
  })

  it('passes AA for the muted text colour on the page and surface backgrounds', () => {
    expect(contrastRatio('#71717a', '#ffffff')).toBeGreaterThanOrEqual(4.5)
    expect(contrastRatio('#71717a', '#fafafa')).toBeGreaterThanOrEqual(4.5)
  })
})
