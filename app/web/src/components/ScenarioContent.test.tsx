import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import type { Scenario } from '@/api/types'

import { ScenarioContent } from './ScenarioContent'

function scenario(overrides: Partial<Scenario> = {}): Scenario {
  return {
    cache_key: 'a'.repeat(64),
    source: 'live',
    text: '',
    sections: {
      natural_language: 'First paragraph (T1190).\n\nSecond paragraph.',
      mathematical: 'N = {n1: Internet}\nG = (N, S, V, P, FS)',
      attack_graph:
        'Stage 1 (Initial Access): Internet [T1190] -> Instance\nFinal Impact: Data lost.',
      preamble: null,
      missing: [],
    },
    reached_token_cap: false,
    hit_eos: true,
    new_tokens: 900,
    max_new_tokens: 1200,
    finish_reason: 'eos',
    seconds: 41.3,
    model_id: 'mistralai/Mistral-7B-Instruct-v0.3',
    model_revision: 'b'.repeat(40),
    adapter_repo: 'owner/adapter',
    adapter_revision: 'c'.repeat(40),
    loading_recipe: 'nf4-dq-unmerged',
    prompt_version: 'P1.v1',
    generation_config: {},
    generated_at: '2026-10-24T10:00:00Z',
    ...overrides,
  }
}

describe('ScenarioContent', () => {
  it('renders the three titled sections', () => {
    render(<ScenarioContent scenario={scenario()} />)
    expect(screen.getByRole('heading', { name: 'Narrative' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Mathematical expression' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Attack graph' })).toBeInTheDocument()
    expect(screen.getByText('Second paragraph.')).toBeInTheDocument()
    expect(screen.getByText('G = (N, S, V, P, FS)')).toBeInTheDocument()

    const graph = screen.getByRole('region', { name: 'Attack graph' })
    const items = within(graph).getAllByRole('listitem')
    expect(items).toHaveLength(1)
    expect(items[0]).toHaveTextContent('Initial Access')
    expect(within(graph).getByText('Data lost.')).toBeInTheDocument()
  })

  it('renders generated markup as text', () => {
    const html = '<img src=x onerror="alert(1)"><b>bold</b>'
    const { container } = render(
      <ScenarioContent
        scenario={scenario({
          sections: {
            natural_language: html,
            mathematical: '<script>x</script>',
            attack_graph: '1. <i>step</i>',
            preamble: '<em>Hi</em>',
            missing: [],
          },
        })}
      />,
    )
    expect(container.querySelector('img, b, script, i, em')).toBeNull()
    expect(screen.getByText(html)).toBeInTheDocument()
    expect(screen.getByText('<em>Hi</em>')).toBeInTheDocument()
  })

  it('shows a muted card for a missing section, with the token limit only when confirmed', () => {
    const sections = {
      natural_language: 'Story.',
      mathematical: 'N = {n1',
      attack_graph: null,
      preamble: null,
      missing: ['attack_graph'],
    }
    const { unmount } = render(
      <ScenarioContent
        scenario={scenario({ sections, reached_token_cap: true, new_tokens: 1200 })}
      />,
    )
    const card = screen.getByRole('region', { name: 'Attack graph missing' })
    expect(card).toHaveTextContent('token limit after 1,200 tokens')
    expect(screen.queryByRole('heading', { name: 'Attack graph' })).toBeNull()
    unmount()

    render(<ScenarioContent scenario={scenario({ sections, reached_token_cap: false })} />)
    expect(screen.getByRole('region', { name: 'Attack graph missing' })).not.toHaveTextContent(
      /token/,
    )
  })

  it('keeps a preamble apart from the narrative', () => {
    render(
      <ScenarioContent
        scenario={scenario({
          sections: {
            natural_language: 'Story.',
            mathematical: 'N',
            attack_graph: '1. A',
            preamble: 'Here is the scenario.',
            missing: [],
          },
        })}
      />,
    )
    const narrative = screen.getByRole('region', { name: 'Narrative' })
    expect(within(narrative).queryByText('Here is the scenario.')).toBeNull()
    expect(screen.getByText('Here is the scenario.')).toBeInTheDocument()
  })
})
