import { Search, X } from 'lucide-react'
import { useId, useMemo, useRef, useState, type KeyboardEvent } from 'react'

import type { GraphViewKind } from '@/api/graph'
import type { Path, Resource } from '@/api/types'
import { LevelBadge } from '@/components/LevelBadge'
import { SeverityDot } from '@/components/SeverityBadge'
import { Input } from '@/components/ui/input'
import { Popover, PopoverAnchor, PopoverContent } from '@/components/ui/popover'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { formatResourceType } from '@/lib/format'
import { resourceTone } from '@/lib/severity'
import { cn } from '@/lib/utils'

import { orderedPaths } from './highlight'

// -- View toggle ----------------------------------------------------------------

export function ViewToggle({
  value,
  onChange,
}: {
  value: GraphViewKind
  onChange: (view: GraphViewKind) => void
}) {
  return (
    <Tabs
      value={value}
      onValueChange={(next) => {
        if (next === 'state' || next === 'attack') onChange(next)
      }}
    >
      <TabsList aria-label="Graph view">
        <TabsTrigger value="state" title="One box per resource, linked as the template declares">
          Resources
        </TabsTrigger>
        <TabsTrigger
          value="attack"
          title="One box per attacker state, linked by the moves between them"
        >
          Attack moves
        </TabsTrigger>
      </TabsList>
    </Tabs>
  )
}

// -- Path picker ----------------------------------------------------------------

const NO_PATH = '__none'

function PathOption({ path }: { path: Path }) {
  return (
    <span className="flex min-w-0 items-center gap-2">
      <span className="font-mono text-dense font-medium tabular-nums">{path.source_id}</span>
      <LevelBadge level={path.attack_level} />
      <span className="truncate text-muted-foreground">{path.objective_name}</span>
    </span>
  )
}

export function PathPicker({
  paths,
  value,
  onChange,
}: {
  paths: readonly Path[]
  value: string | null
  onChange: (sourceId: string | null) => void
}) {
  const ordered = useMemo(() => orderedPaths(paths), [paths])
  const exported = ordered.filter((path) => path.exported)
  const rest = ordered.filter((path) => !path.exported)
  return (
    <Select
      value={value ?? NO_PATH}
      onValueChange={(next) => onChange(next === NO_PATH ? null : next)}
      disabled={paths.length === 0}
    >
      <SelectTrigger aria-label="Highlight a path" className="w-[23rem] max-w-full">
        <SelectValue placeholder="Highlight a path" />
      </SelectTrigger>
      <SelectContent className="max-h-96 w-[23rem]">
        <SelectItem value={NO_PATH}>
          <span className="text-muted-foreground">No path highlighted</span>
        </SelectItem>
        {exported.length > 0 && (
          <SelectGroup>
            <SelectSeparator />
            <SelectLabel>Exported paths</SelectLabel>
            {exported.map((path) => (
              <SelectItem key={path.source_id} value={path.source_id}>
                <PathOption path={path} />
              </SelectItem>
            ))}
          </SelectGroup>
        )}
        {rest.length > 0 && (
          <SelectGroup>
            <SelectSeparator />
            <SelectLabel>Below the minimum level</SelectLabel>
            {rest.map((path) => (
              <SelectItem key={path.source_id} value={path.source_id}>
                <PathOption path={path} />
              </SelectItem>
            ))}
          </SelectGroup>
        )}
      </SelectContent>
    </Select>
  )
}

// -- Resource search --------------------------------------------------------------

const MAX_RESULTS = 50

export function ResourceSearch({
  resources,
  isAvailable,
  onSelect,
}: {
  resources: readonly Resource[]
  /** False for a resource the current view does not draw. */
  isAvailable: (id: string) => boolean
  onSelect: (id: string) => void
}) {
  const listId = useId()
  const anchorRef = useRef<HTMLDivElement>(null)
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)

  const results = useMemo(() => {
    const needle = query.trim().toLowerCase()
    const matches = needle
      ? resources.filter(
          (resource) =>
            resource.id.toLowerCase().includes(needle) ||
            resource.type.toLowerCase().includes(needle),
        )
      : [...resources]
    // Drawn resources first, then by name.
    matches.sort(
      (a, b) => Number(isAvailable(b.id)) - Number(isAvailable(a.id)) || a.id.localeCompare(b.id),
    )
    return matches.slice(0, MAX_RESULTS)
  }, [resources, query, isAvailable])

  const showList = open && results.length > 0

  const choose = (resource: Resource | undefined) => {
    if (!resource || !isAvailable(resource.id)) return
    setQuery(resource.id)
    setOpen(false)
    onSelect(resource.id)
  }

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault()
      setOpen(true)
      const step = event.key === 'ArrowDown' ? 1 : -1
      setActive((index) =>
        results.length === 0 ? 0 : (index + step + results.length) % results.length,
      )
    } else if (event.key === 'Enter') {
      event.preventDefault()
      choose(results[active])
    } else if (event.key === 'Escape') {
      // The popover leaves Escape to this handler (onEscapeKeyDown below), so it
      // sees the list as it was: the first press closes it, the next clears the text.
      if (showList) setOpen(false)
      else if (query) setQuery('')
    }
  }

  const optionId = (index: number) => `${listId}-option-${String(index)}`

  return (
    <Popover open={showList} onOpenChange={setOpen}>
      <PopoverAnchor asChild>
        <div ref={anchorRef} className="relative w-64 max-w-full">
          <Search
            aria-hidden="true"
            className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground"
          />
          <Input
            role="combobox"
            aria-label="Find a resource"
            aria-expanded={showList}
            aria-controls={listId}
            aria-autocomplete="list"
            aria-activedescendant={showList ? optionId(active) : undefined}
            placeholder="Find a resource"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value)
              setActive(0)
              setOpen(true)
            }}
            onFocus={() => setOpen(true)}
            onClick={() => setOpen(true)}
            onKeyDown={onKeyDown}
            className="pr-8 pl-8"
            spellCheck={false}
            autoComplete="off"
          />
          {query && (
            <button
              type="button"
              aria-label="Clear search"
              className="absolute top-1/2 right-1.5 flex size-5 -translate-y-1/2 cursor-pointer items-center justify-center rounded-sm text-muted-foreground hover:bg-subtle hover:text-foreground"
              onClick={() => {
                setQuery('')
                setActive(0)
              }}
            >
              <X className="size-3.5" />
            </button>
          )}
        </div>
      </PopoverAnchor>
      <PopoverContent
        align="start"
        className="w-80 gap-0 p-1"
        onOpenAutoFocus={(event) => event.preventDefault()}
        onCloseAutoFocus={(event) => event.preventDefault()}
        onEscapeKeyDown={(event) => event.preventDefault()}
        onInteractOutside={(event) => {
          if (anchorRef.current?.contains(event.target as Node)) event.preventDefault()
        }}
      >
        <ul id={listId} role="listbox" aria-label="Resources" className="max-h-72 overflow-y-auto">
          {results.map((resource, index) => {
            const available = isAvailable(resource.id)
            return (
              <li
                key={resource.id}
                id={optionId(index)}
                role="option"
                aria-selected={index === active}
                aria-disabled={!available}
                onPointerMove={() => setActive(index)}
                onPointerDown={(event) => event.preventDefault()}
                onClick={() => choose(resource)}
                className={cn(
                  'flex h-8 cursor-pointer items-center gap-2 rounded-md px-2 text-dense',
                  index === active && 'bg-subtle',
                  !available && 'cursor-default opacity-50',
                )}
              >
                <SeverityDot severity={resourceTone(resource.max_severity)} />
                <span className="truncate font-mono text-xs font-medium">{resource.id}</span>
                <span className="ml-auto shrink-0 truncate pl-2 text-xs text-muted-foreground">
                  {available ? formatResourceType(resource.type) : 'not in this view'}
                </span>
              </li>
            )
          })}
        </ul>
      </PopoverContent>
    </Popover>
  )
}
