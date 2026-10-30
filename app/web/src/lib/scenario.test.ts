import { describe, expect, it } from 'vitest'

import { parseRetryAfter } from '@/api/client'

import { retryAfterText } from './format'
import {
  formatElapsed,
  humanizeTimestamps,
  isActiveStatus,
  isResultStatus,
  missingSectionCopy,
  parseAttackGraph,
  progressCopy,
  repoName,
  retryAfterSuffix,
  sectionTitle,
  sourceLabel,
  splitArrows,
  splitLines,
  splitParagraphs,
  splitTechniqueIds,
  statusAnnouncement,
  truncationNote,
} from './scenario'

describe('status groups', () => {
  it('polls only while a job is queued, warming up or running', () => {
    expect(isActiveStatus('queued')).toBe(true)
    expect(isActiveStatus('warming_up')).toBe(true)
    expect(isActiveStatus('running')).toBe(true)
    for (const status of ['idle', 'done', 'cached', 'failed'] as const) {
      expect(isActiveStatus(status)).toBe(false)
    }
    expect(isActiveStatus(undefined)).toBe(false)
  })

  it('treats done and cached as results', () => {
    expect(isResultStatus('done')).toBe(true)
    expect(isResultStatus('cached')).toBe(true)
    expect(isResultStatus('failed')).toBe(false)
    expect(isResultStatus('running')).toBe(false)
  })
})

describe('progressCopy', () => {
  it('names the jobs ahead in the queue', () => {
    expect(progressCopy('queued', 2, null).button).toBe('Queued · 2 ahead')
    expect(progressCopy('queued', 1, null).detail).toMatch(/^Waiting for 1 generation ahead/)
    expect(progressCopy('queued', 3, null).detail).toMatch(/^Waiting for 3 generations ahead/)
  })

  it('does not say "0 ahead"', () => {
    expect(progressCopy('queued', 0, null).button).toBe('Queued')
    expect(progressCopy('queued', null, null).button).toBe('Queued')
    expect(progressCopy('queued', 0, null).detail).toMatch(/^Next in line/)
  })

  it('warns that warming up can take minutes', () => {
    const copy = progressCopy('warming_up', null, 12)
    expect(copy.button).toBe('Starting the model…')
    expect(copy.detail).toMatch(/^Starting the model, this can take a few minutes/)
  })

  it('counts whole seconds while running', () => {
    expect(progressCopy('running', null, 12.7).button).toBe('Generating… 12 s')
    expect(progressCopy('running', null, null).button).toBe('Generating… 0 s')
    expect(progressCopy('running', null, 125).button).toBe('Generating… 2 min 5 s')
  })

  it('never mentions a number of generations left', () => {
    for (const status of ['queued', 'warming_up', 'running'] as const) {
      const copy = progressCopy(status, 2, 30)
      expect(`${copy.button} ${copy.detail}`).not.toMatch(/left/i)
    }
  })
})

describe('formatElapsed', () => {
  it('formats whole seconds and minutes', () => {
    expect(formatElapsed(0)).toBe('0 s')
    expect(formatElapsed(59.9)).toBe('59 s')
    expect(formatElapsed(60)).toBe('1 min')
    expect(formatElapsed(61)).toBe('1 min 1 s')
    expect(formatElapsed(-3)).toBe('0 s')
  })
})

describe('statusAnnouncement', () => {
  it('speaks each state once, without a ticking count', () => {
    expect(statusAnnouncement('queued', 2)).toBe('Scenario queued, 2 ahead.')
    expect(statusAnnouncement('queued', 0)).toBe('Scenario queued.')
    expect(statusAnnouncement('warming_up')).toMatch(/^Starting the model/)
    expect(statusAnnouncement('running')).toBe('Generating the scenario.')
    expect(statusAnnouncement('done')).toBe('Scenario ready.')
    expect(statusAnnouncement('cached')).toBe('Scenario ready.')
    expect(statusAnnouncement('failed')).toBe('Scenario generation failed.')
    expect(statusAnnouncement('idle')).toBe('')
  })
})

describe('Retry-After', () => {
  const now = Date.parse('2026-10-24T12:00:00Z')

  it('parses delta seconds and HTTP dates', () => {
    expect(parseRetryAfter('30', now)).toBe(30)
    expect(parseRetryAfter(' 120 ', now)).toBe(120)
    expect(parseRetryAfter('Sat, 24 Oct 2026 12:05:00 GMT', now)).toBe(300)
    expect(parseRetryAfter('Sat, 24 Oct 2026 11:00:00 GMT', now)).toBe(0)
    expect(parseRetryAfter(null, now)).toBeNull()
    expect(parseRetryAfter('soon', now)).toBeNull()
  })

  it('says when to try again', () => {
    const at = new Date(now)
    expect(retryAfterText(30, at)).toBe('Try again in 30 s.')
    expect(retryAfterText(0, at)).toBe('Try again in 1 s.')
    expect(retryAfterText(600, at)).toBe('Try again in about 10 min.')
    expect(retryAfterText(7200, at)).toBe('Try again after 24 Oct 2026, 14:00 UTC.')
    expect(retryAfterText(7198, at)).toBe('Try again after 24 Oct 2026, 14:00 UTC.')
  })

  it('does not repeat a time the server already names', () => {
    const at = new Date(now)
    const quota = 'The quota is used up until 2026-10-24T14:00:00+00:00.'
    expect(retryAfterSuffix(quota, 7198, at)).toBeNull()
    expect(retryAfterSuffix('The scenario queue is full (20 waiting).', 30, at)).toBe(
      'Try again in 30 s.',
    )
    expect(retryAfterSuffix('Busy.', 7200, at)).toBe('Try again after 24 Oct 2026, 14:00 UTC.')
  })

  it('writes ISO timestamps in server messages as app dates', () => {
    expect(humanizeTimestamps('The quota is used up until 2026-10-25T11:00:00+00:00.')).toBe(
      'The quota is used up until 25 Oct 2026, 11:00 UTC.',
    )
    expect(humanizeTimestamps('At 2026-10-24T09:30Z and 2026-10-24T12:00:00.5+02:00.')).toBe(
      'At 24 Oct 2026, 09:30 UTC and 24 Oct 2026, 10:00 UTC.',
    )
    expect(humanizeTimestamps('No dates here.')).toBe('No dates here.')
  })
})

describe('sections', () => {
  it('titles the three sections', () => {
    expect(sectionTitle('natural_language')).toBe('Narrative')
    expect(sectionTitle('mathematical')).toBe('Mathematical expression')
    expect(sectionTitle('attack_graph')).toBe('Attack graph')
    expect(sectionTitle('something_new')).toBe('Something new')
  })

  it('names the token limit only when the cap is confirmed', () => {
    const capped = missingSectionCopy('attack_graph', { reached_token_cap: true, new_tokens: 1200 })
    expect(capped.title).toBe('Attack graph missing')
    expect(capped.description).toBe(
      'The model reached its token limit after 1,200 tokens, before writing this section.',
    )

    const absent = missingSectionCopy('attack_graph', { reached_token_cap: false, new_tokens: 640 })
    expect(absent.description).toBe("The model's output has no attack graph section.")
    expect(absent.description).not.toMatch(/limit|token/)
  })

  it('notes a confirmed cap when every section is present', () => {
    const sections = {
      natural_language: 'a',
      mathematical: 'b',
      attack_graph: 'c',
      preamble: null,
      missing: [],
    }
    expect(truncationNote({ reached_token_cap: true, new_tokens: 1200, sections })).toMatch(
      /token limit after 1,200 tokens/,
    )
    expect(truncationNote({ reached_token_cap: false, new_tokens: 1200, sections })).toBeNull()
    expect(
      truncationNote({
        reached_token_cap: true,
        new_tokens: 1200,
        sections: { ...sections, attack_graph: null, missing: ['attack_graph'] },
      }),
    ).toBeNull()
  })

  it('splits prose on blank lines and keeps single breaks', () => {
    expect(splitParagraphs('One.\nStill one.\n\n  Two.  \n \n\nThree.')).toEqual([
      'One.\nStill one.',
      'Two.',
      'Three.',
    ])
    expect(splitParagraphs('   ')).toEqual([])
  })

  it('drops blank lines', () => {
    expect(splitLines('N = {n1}\n\nS = {s1}   \n')).toEqual(['N = {n1}', 'S = {s1}'])
  })
})

describe('parseAttackGraph', () => {
  it('lists numbered lines', () => {
    expect(parseAttackGraph('1. Scan\n2. Exploit -> Shell')).toEqual({
      kind: 'list',
      intro: [],
      stages: [
        { number: 1, label: null, text: 'Scan' },
        { number: 2, label: null, text: 'Exploit -> Shell' },
      ],
      finalImpact: null,
      after: [],
    })
  })

  it('reads the training format with tactics and a final impact', () => {
    const graph = parseAttackGraph(
      [
        'Stage 1 (Initial Access): Internet [T1190] -> PublicEC2Instance',
        'Stage 2 (Credential Access): PublicEC2Instance [T1552.005] -> Profile',
        'Final Impact: Data encrypted for ransom.',
      ].join('\n'),
    )
    expect(graph).toEqual({
      kind: 'list',
      intro: [],
      stages: [
        { number: 1, label: 'Initial Access', text: 'Internet [T1190] -> PublicEC2Instance' },
        { number: 2, label: 'Credential Access', text: 'PublicEC2Instance [T1552.005] -> Profile' },
      ],
      finalImpact: 'Data encrypted for ransom.',
      after: [],
    })
  })

  it('folds continuation lines into their stage and keeps an intro', () => {
    const graph = parseAttackGraph(
      'The chain:\nStage 1: Phish\nPrecondition: mail access\nStage 2: Pivot\nClosing words.',
    )
    expect(graph.kind).toBe('list')
    if (graph.kind !== 'list') return
    expect(graph.intro).toEqual(['The chain:'])
    expect(graph.stages).toEqual([
      { number: 1, label: null, text: 'Phish\nPrecondition: mail access' },
      { number: 2, label: null, text: 'Pivot\nClosing words.' },
    ])
  })

  it('keeps lines after the final impact apart', () => {
    const graph = parseAttackGraph('1. A\nFinal Impact: B\nC')
    expect(graph.kind === 'list' && graph.after).toEqual(['C'])
  })

  it('leaves unnumbered text as lines', () => {
    expect(parseAttackGraph('Internet -> Instance\nInstance -> Role')).toEqual({
      kind: 'text',
      lines: ['Internet -> Instance', 'Instance -> Role'],
    })
  })
})

describe('text parts', () => {
  it('sets technique ids apart and loses nothing', () => {
    const text = 'Shell (T1190), then IMDS [T1552.005]; not XT1234 or T12.'
    const parts = splitTechniqueIds(text)
    expect(parts.map((p) => p.text).join('')).toBe(text)
    expect(parts.filter((p) => p.technique).map((p) => p.text)).toEqual(['T1190', 'T1552.005'])
  })

  it('splits plain-text arrows', () => {
    expect(splitArrows('Internet [T1190] -> Instance->Role')).toEqual([
      'Internet [T1190]',
      'Instance',
      'Role',
    ])
    expect(splitArrows('No arrows')).toEqual(['No arrows'])
  })
})

describe('provenance', () => {
  it('labels the source and shortens repo ids', () => {
    expect(sourceLabel('live')).toBe('Live')
    expect(sourceLabel('pregenerated')).toBe('Pre-generated')
    expect(repoName('mistralai/Mistral-7B-Instruct-v0.3')).toBe('Mistral-7B-Instruct-v0.3')
    expect(repoName('plain')).toBe('plain')
  })
})
