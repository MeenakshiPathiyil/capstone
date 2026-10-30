import { Download, Inbox, Plus, Search } from 'lucide-react'
import { useState, type ReactNode } from 'react'

import { AppShell, Container } from '@/components/AppShell'
import { BarRow } from '@/components/BarRow'
import { ChainDiagram, type ChainNode } from '@/components/ChainDiagram'
import { EmptyState } from '@/components/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { LevelBadge } from '@/components/LevelBadge'
import { ScoreBar } from '@/components/ScoreBar'
import { SeverityBadge, SeverityDot } from '@/components/SeverityBadge'
import {
  AnalysisHeaderSkeleton,
  CardListSkeleton,
  StatTilesSkeleton,
  TableSkeleton,
} from '@/components/Skeletons'
import { Spinner } from '@/components/Spinner'
import { StatTile } from '@/components/StatTile'
import { TechniqueChip } from '@/components/TechniqueChip'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Popover,
  PopoverContent,
  PopoverDescription,
  PopoverHeader,
  PopoverTitle,
  PopoverTrigger,
} from '@/components/ui/popover'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { AnalysisLayout, MetaDot } from '@/pages/AnalysisLayout'
import { chainText, formatCount, formatDateTime, formatFactor, formatScore } from '@/lib/format'
import {
  ATTACK_LEVELS,
  contrastRatio,
  DEFAULT_SEVERITY_STYLES,
  levelTone,
  SEVERITIES,
  severityLabel,
  TONES,
  type AttackLevel,
  type Severity,
} from '@/lib/severity'
import type { AnalysisTab } from '@/lib/tabs'

// -- Fixture data: the bundled sample's real numbers and names ------------------------

const NODE = {
  OpenSecurityGroup: { type: 'AWS::EC2::SecurityGroup', tone: 'high', isEntry: true },
  PublicEC2Instance: { type: 'AWS::EC2::Instance', tone: 'critical', isEntry: true },
  OverPermissiveInstanceProfile: { type: 'AWS::IAM::InstanceProfile', tone: 'clean' },
  OverPermissiveRole: { type: 'AWS::IAM::Role', tone: 'critical' },
  InsecureS3Bucket: { type: 'AWS::S3::Bucket', tone: 'high', isEntry: true },
  AppSecurityGroup: { type: 'AWS::EC2::SecurityGroup', tone: 'high', isEntry: true },
  AppServerInstance: { type: 'AWS::EC2::Instance', tone: 'critical', isEntry: true },
  AppInstanceProfile: { type: 'AWS::IAM::InstanceProfile', tone: 'clean' },
  AppServerRole: { type: 'AWS::IAM::Role', tone: 'high' },
  DeploymentRole: { type: 'AWS::IAM::Role', tone: 'critical' },
  PublicRDS: { type: 'AWS::RDS::DBInstance', tone: 'high', isEntry: true },
  ReportsTable: { type: 'AWS::DynamoDB::Table', tone: 'clean' },
} as const satisfies Record<string, Omit<ChainNode, 'id'>>

type NodeId = keyof typeof NODE

/** A path's chain. Only the first hop is drawn as the entry, as on a path. */
function chain(ids: readonly NodeId[]): ChainNode[] {
  return ids.map((id, index) => ({ id, ...NODE[id], isEntry: index === 0 }))
}

const AP_001 = chain([
  'OpenSecurityGroup',
  'PublicEC2Instance',
  'OverPermissiveInstanceProfile',
  'OverPermissiveRole',
  'InsecureS3Bucket',
])
const AP_007 = chain([
  'AppSecurityGroup',
  'AppServerInstance',
  'AppInstanceProfile',
  'AppServerRole',
  'DeploymentRole',
  'OverPermissiveRole',
  'InsecureS3Bucket',
])
const LONG_IDS: ChainNode[] = [
  {
    id: 'PublicFacingApplicationLoadBalancerSecurityGroupIngressFromAnywhere',
    type: 'AWS::EC2::SecurityGroup',
    tone: 'high',
    isEntry: true,
  },
  {
    id: 'NestedStackPaymentsServiceAutoScalingGroupLaunchTemplate',
    type: 'AWS::EC2::LaunchTemplate',
    tone: 'medium',
  },
  { id: 'PaymentsServiceInstanceProfile', type: 'AWS::IAM::InstanceProfile', tone: 'clean' },
  {
    id: 'PaymentsServiceExecutionRoleWithWildcardPassRole',
    type: 'AWS::IAM::Role',
    tone: 'critical',
  },
  { id: 'CrossAccountDeploymentRole', type: 'AWS::IAM::Role', tone: 'unknown' },
  { id: 'LedgerExportsBucket', type: 'AWS::S3::Bucket', tone: 'low' },
  { id: 'Custom::ThirdPartyAuditHook', type: 'Custom::AuditHook', tone: 'clean' },
]
const AP_001_TECHNIQUES = ['T1190', 'T1552.005', 'T1550', 'T1098.001']

const PATHS: {
  id: string
  level: AttackLevel
  score: number
  objective: string
  hops: NodeId[]
}[] = [
  {
    id: 'AP-001',
    level: 'CRITICAL',
    score: 56.04,
    objective: 'Ransomware',
    hops: [
      'OpenSecurityGroup',
      'PublicEC2Instance',
      'OverPermissiveInstanceProfile',
      'OverPermissiveRole',
      'InsecureS3Bucket',
    ],
  },
  {
    id: 'AP-002',
    level: 'CRITICAL',
    score: 55.27,
    objective: 'Data theft',
    hops: [
      'OpenSecurityGroup',
      'PublicEC2Instance',
      'OverPermissiveInstanceProfile',
      'OverPermissiveRole',
      'InsecureS3Bucket',
    ],
  },
  {
    id: 'AP-007',
    level: 'CRITICAL',
    score: 46.03,
    objective: 'Ransomware',
    hops: [
      'AppSecurityGroup',
      'AppServerInstance',
      'AppInstanceProfile',
      'AppServerRole',
      'DeploymentRole',
      'OverPermissiveRole',
      'InsecureS3Bucket',
    ],
  },
  {
    id: 'AP-015',
    level: 'HIGH',
    score: 37.5,
    objective: 'Denial of service',
    hops: ['OpenSecurityGroup', 'PublicEC2Instance'],
  },
  {
    id: 'AP-019',
    level: 'HIGH',
    score: 30.0,
    objective: 'Denial of service',
    hops: ['AppSecurityGroup', 'AppServerInstance'],
  },
  {
    id: 'AP-020',
    level: 'MEDIUM',
    score: 28.9,
    objective: 'Identity takeover',
    hops: ['AppSecurityGroup', 'AppServerInstance', 'AppInstanceProfile', 'AppServerRole'],
  },
]

const FINDINGS_BY_SEVERITY: Record<Severity, number> = {
  critical: 6,
  high: 12,
  medium: 0,
  low: 4,
  unknown: 0,
}
const PATHS_BY_LEVEL: Record<AttackLevel, number> = { CRITICAL: 14, HIGH: 5, MEDIUM: 3 }

const FINDINGS: {
  severity: Severity
  resource: string
  type: string
  finding: string
  semantic: string
  techniques: string[]
  paths: number
}[] = [
  {
    severity: 'critical',
    resource: 'OverPermissiveRole',
    type: 'AWS::IAM::Role',
    finding: 'Creating a new policy version',
    semantic: 'privilege',
    techniques: ['T1098.003', 'T1548.005'],
    paths: 14,
  },
  {
    severity: 'critical',
    resource: 'PublicEC2Instance',
    type: 'AWS::EC2::Instance',
    finding: 'Instance metadata service v1 enabled',
    semantic: 'identity',
    techniques: ['T1552.005'],
    paths: 7,
  },
  {
    severity: 'high',
    resource: 'OpenSecurityGroup',
    type: 'AWS::EC2::SecurityGroup',
    finding: 'SSH open to the internet',
    semantic: 'network_control',
    techniques: ['T1190', 'T1021.004'],
    paths: 7,
  },
  {
    severity: 'high',
    resource: 'InsecureS3Bucket',
    type: 'AWS::S3::Bucket',
    finding: 'Bucket allows public read',
    semantic: 'exposure',
    techniques: ['T1530'],
    paths: 4,
  },
  {
    severity: 'low',
    resource: 'AppServerInstance',
    type: 'AWS::EC2::Instance',
    finding: 'Required tags missing',
    semantic: 'capability',
    techniques: [],
    paths: 0,
  },
]

// -- Page ---------------------------------------------------------------------------

const SECTIONS = [
  ['colour', 'Colour'],
  ['type', 'Typography'],
  ['badges', 'Badges'],
  ['buttons', 'Buttons and fields'],
  ['stats', 'Stat tiles'],
  ['bars', 'Bars and scores'],
  ['chains', 'Chain diagram'],
  ['table', 'Dense table'],
  ['tabs', 'Tabs'],
  ['overlays', 'Overlays'],
  ['states', 'Empty, error, loading'],
  ['layout', 'Analysis layout'],
] as const

export default function KitchenSinkPage() {
  return (
    <AppShell headerActions={<Badge variant="secondary">Dev only</Badge>}>
      <Container className="grid grid-cols-[11rem_minmax(0,1fr)] gap-10 py-10">
        <nav aria-label="Sections" className="sticky top-20 self-start">
          <p className="mb-2 px-2 text-xs font-medium text-muted-foreground">Kitchen sink</p>
          <ul className="flex flex-col">
            {SECTIONS.map(([id, label]) => (
              <li key={id}>
                <a
                  href={`#${id}`}
                  className="block rounded-md px-2 py-1 text-dense text-muted-foreground hover:bg-subtle hover:text-foreground"
                >
                  {label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <div className="flex min-w-0 flex-col gap-14">
          <header>
            <h1 className="text-2xl font-semibold">Design system</h1>
            <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
              Every primitive in every state, with the bundled sample&apos;s real names and numbers.
              Colour carries meaning only: severity for findings and resources, level for paths.
            </p>
          </header>
          <ColourSection />
          <TypeSection />
          <BadgeSection />
          <ButtonSection />
          <StatSection />
          <BarSection />
          <ChainSection />
          <TableSection />
          <TabsSection />
          <OverlaySection />
          <StatesSection />
          <LayoutSection />
        </div>
      </Container>
    </AppShell>
  )
}

function Section({
  id,
  title,
  description,
  children,
}: {
  id: string
  title: string
  description?: string
  children: ReactNode
}) {
  return (
    <section id={id} aria-labelledby={`${id}-title`} className="scroll-mt-20">
      <h2 id={`${id}-title`} className="text-lg font-semibold">
        {title}
      </h2>
      {description && (
        <p className="mt-1 max-w-2xl text-dense text-muted-foreground">{description}</p>
      )}
      <div className="mt-4 flex flex-col gap-4">{children}</div>
    </section>
  )
}

function Panel({
  title,
  className,
  children,
}: {
  title?: string
  className?: string
  children: ReactNode
}) {
  return (
    <div className={`rounded-lg border bg-surface ${className ?? ''}`}>
      {title && (
        <div className="border-b px-4 py-2.5 text-xs font-medium text-muted-foreground">
          {title}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  )
}

// -- Sections -----------------------------------------------------------------------

function ColourSection() {
  return (
    <Section
      id="colour"
      title="Colour"
      description="Fill and stroke come from SEVERITY_STYLES via /api/meta. Tint, solid and line are derived in CSS with color-mix, so they follow the served palette."
    >
      <div className="grid grid-cols-3 gap-3">
        {TONES.map((tone) => {
          const { fill, stroke } = DEFAULT_SEVERITY_STYLES[tone]
          const ratio = contrastRatio(stroke, fill)
          return (
            <div
              key={tone}
              data-tone={tone}
              className="overflow-hidden rounded-lg border bg-surface"
            >
              <div className="flex h-14 items-end justify-between bg-tone-fill px-3 pb-2 text-tone-stroke">
                <span className="text-sm font-semibold">{severityLabel(tone)}</span>
                <span className="font-mono text-2xs">{tone}</span>
              </div>
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 px-3 py-2.5 text-xs">
                <Swatch label="fill" className="bg-tone-fill" value={fill} />
                <Swatch label="stroke" className="bg-tone-stroke" value={stroke} />
                <Swatch label="tint" className="bg-tone-tint" value="fill 45% + white" />
                <Swatch
                  label="solid"
                  className="bg-tone-solid"
                  value={`fill ${tone === 'medium' ? '72' : '55'}% + stroke, chroma ×1.6`}
                />
                <dt className="text-muted-foreground">contrast</dt>
                <dd className="font-mono text-2xs tabular-nums">
                  {ratio.toFixed(2)}:1 stroke on fill {ratio >= 4.5 ? '(AA)' : '(fails AA)'}
                </dd>
              </dl>
            </div>
          )
        })}
      </div>
      <Panel title="Neutrals">
        <div className="flex flex-wrap gap-3 text-2xs">
          {[
            ['background', 'bg-background'],
            ['surface', 'bg-surface'],
            ['subtle', 'bg-subtle'],
            ['border', 'bg-border'],
            ['border-strong', 'bg-border-strong'],
            ['faint', 'bg-faint'],
            ['muted-foreground', 'bg-muted-foreground'],
            ['foreground', 'bg-foreground'],
          ].map(([name, cls]) => (
            <div key={name} className="flex w-24 flex-col gap-1.5">
              <span className={`h-10 rounded-md border ${cls ?? ''}`} />
              <span className="font-mono text-muted-foreground">{name}</span>
            </div>
          ))}
        </div>
      </Panel>
    </Section>
  )
}

function Swatch({ label, className, value }: { label: string; className: string; value: string }) {
  return (
    <>
      <dt className="flex items-center gap-1.5 text-muted-foreground">
        <span className={`size-3 rounded-sm border border-tone-line/30 ${className}`} />
        {label}
      </dt>
      <dd className="truncate font-mono text-2xs">{value}</dd>
    </>
  )
}

function TypeSection() {
  const rows: [string, string, ReactNode][] = [
    ['2xl / 24 semibold', 'text-2xl font-semibold', 'Analyse a CloudFormation template'],
    ['xl / 20 semibold', 'text-xl font-semibold', 'cloudformation5.yml'],
    ['lg / 18 semibold', 'text-lg font-semibold', 'Top paths'],
    ['base / 16 semibold', 'text-base font-semibold', 'Fix impact'],
    ['sm / 14 body', 'text-sm', 'Finds misconfigurations and IAM privilege escalations.'],
    ['dense / 13 tables', 'text-dense', 'SSH open to the internet on OpenSecurityGroup'],
    [
      'xs / 12 meta',
      'text-xs text-muted-foreground',
      'Information technology service activities (ISIC J62)',
    ],
    ['2xs / 11 micro', 'text-2xs font-medium text-muted-foreground', 'EC2 SecurityGroup · entry'],
    ['mono / 12', 'font-mono text-xs', 'arn:aws:iam::123456789012:role/OverPermissiveRole'],
    ['numbers', 'text-2xl font-semibold tabular-nums', '56.04  22  1,234  0.85'],
  ]
  return (
    <Section
      id="type"
      title="Typography"
      description="Inter for the interface, Geist Mono for ids, ARNs, technique ids and code. Tabular numbers wherever numbers line up. Headings tighten their tracking as they grow."
    >
      <Panel>
        <dl className="flex flex-col divide-y">
          {rows.map(([label, cls, sample]) => (
            <div
              key={label}
              className="grid grid-cols-[10rem_minmax(0,1fr)] items-baseline gap-4 py-2.5 first:pt-0 last:pb-0"
            >
              <dt className="font-mono text-2xs text-muted-foreground">{label}</dt>
              <dd className={`truncate ${cls}`}>{sample}</dd>
            </div>
          ))}
        </dl>
      </Panel>
    </Section>
  )
}

function BadgeSection() {
  return (
    <Section
      id="badges"
      title="Badges"
      description="Severity belongs to a finding or resource: tinted with a dot, sentence case. Level belongs to a path: solid fill, upper case. The shapes differ so the two never read as the same thing."
    >
      <Panel>
        <div className="grid grid-cols-[9rem_minmax(0,1fr)] items-center gap-x-4 gap-y-4">
          <span className="text-xs text-muted-foreground">SeverityBadge soft</span>
          <div className="flex flex-wrap gap-2">
            {TONES.map((t) => (
              <SeverityBadge key={t} severity={t} />
            ))}
          </div>
          <span className="text-xs text-muted-foreground">with count</span>
          <div className="flex flex-wrap gap-2">
            {SEVERITIES.map((s) => (
              <SeverityBadge key={s} severity={s}>
                {severityLabel(s)} {FINDINGS_BY_SEVERITY[s]}
              </SeverityBadge>
            ))}
          </div>
          <span className="text-xs text-muted-foreground">SeverityBadge dot</span>
          <div className="flex flex-wrap gap-4">
            {TONES.map((t) => (
              <SeverityBadge key={t} severity={t} variant="dot" />
            ))}
          </div>
          <span className="text-xs text-muted-foreground">SeverityDot</span>
          <div className="flex flex-wrap gap-3">
            {TONES.map((t) => (
              <SeverityDot key={t} severity={t} />
            ))}
          </div>
          <span className="text-xs text-muted-foreground">LevelBadge</span>
          <div className="flex flex-wrap gap-2">
            {ATTACK_LEVELS.map((l) => (
              <LevelBadge key={l} level={l} />
            ))}
          </div>
          <span className="text-xs text-muted-foreground">Neutral</span>
          <div className="flex flex-wrap items-center gap-2">
            <Badge>Exported</Badge>
            <Badge variant="secondary">Pre-generated</Badge>
            <Badge variant="outline">Below minimum level</Badge>
            <Badge variant="outline" className="font-mono">
              AP-001
            </Badge>
          </div>
          <span className="text-xs text-muted-foreground">TechniqueChip</span>
          <div className="flex flex-wrap gap-1.5">
            <TechniqueChip id="T1190" name="Exploit Public-Facing Application" />
            <TechniqueChip
              id="T1552.005"
              name="Unsecured Credentials: Cloud Instance Metadata API"
            />
            <TechniqueChip id="T1098.001" />
            <TechniqueChip id="fallback" />
          </div>
        </div>
      </Panel>
    </Section>
  )
}

function ButtonSection() {
  const [level, setLevel] = useState('HIGH')
  return (
    <Section
      id="buttons"
      title="Buttons and fields"
      description="32px controls, 6px radius, no shadows. Tab through them: every one shows a focus ring."
    >
      <Panel>
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-2">
            <Button>Analyse template</Button>
            <Button variant="outline">
              <Download />
              Download report
            </Button>
            <Button variant="secondary">Secondary</Button>
            <Button variant="ghost">Ghost</Button>
            <Button variant="destructive">Delete analysis</Button>
            <Button variant="link">View on ATT&amp;CK</Button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button size="lg">Large</Button>
            <Button>Default</Button>
            <Button size="sm" variant="outline">
              <Plus />
              Small
            </Button>
            <Button size="xs" variant="outline">
              Extra small
            </Button>
            <Button size="icon" variant="outline" aria-label="Search">
              <Search />
            </Button>
            <Button size="icon-sm" variant="ghost" aria-label="Search">
              <Search />
            </Button>
            <Button disabled>
              <Spinner />
              Analysing
            </Button>
            <Button variant="outline" disabled>
              Disabled
            </Button>
          </div>
          <div className="grid max-w-2xl grid-cols-[minmax(0,1fr)_12rem] gap-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ks-industry">Industry</Label>
              <Input
                id="ks-industry"
                defaultValue="Information technology service activities (ISIC J62)"
              />
              <p className="text-xs text-muted-foreground">Helper text sits 6px under the field.</p>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ks-level">Minimum level</Label>
              <Select value={level} onValueChange={setLevel}>
                <SelectTrigger id="ks-level" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="CRITICAL">Critical only</SelectItem>
                  <SelectItem value="HIGH">High and above</SelectItem>
                  <SelectItem value="MEDIUM">All paths</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ks-invalid">Invalid</Label>
              <Input id="ks-invalid" aria-invalid defaultValue="" placeholder="Required" />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ks-disabled">Disabled</Label>
              <Input id="ks-disabled" disabled defaultValue="Read only" />
            </div>
          </div>
        </div>
      </Panel>
    </Section>
  )
}

function StatSection() {
  return (
    <Section
      id="stats"
      title="Stat tiles"
      description="The overview's five counts. The number is the point; the label says what it counts."
    >
      <div className="grid grid-cols-5 gap-3">
        <StatTile label="Resources" value={15} hint="16 dependency edges" />
        <StatTile label="Findings" value={22} hint="6 critical, 12 high" />
        <StatTile label="Attack paths" value={22} hint="19 at or above High" />
        <StatTile label="Entry points" value={7} hint="Reachable from the internet" />
        <StatTile
          label="Top score"
          value={formatScore(56.04)}
          hint="AP-001, Critical"
          tone="critical"
        />
      </div>
      <StatTilesSkeleton />
    </Section>
  )
}

function BarSection() {
  const findingMax = Math.max(...Object.values(FINDINGS_BY_SEVERITY))
  const levelMax = Math.max(...Object.values(PATHS_BY_LEVEL))
  const top = PATHS[0]?.score ?? 1
  return (
    <Section
      id="bars"
      title="Bars and scores"
      description="BarRow for distributions, ScoreBar for a path's score against the top score. Ticks mark the High (30) and Critical (40) thresholds."
    >
      <div className="grid grid-cols-2 gap-3">
        <Panel title="Findings by severity">
          {SEVERITIES.map((s) => (
            <BarRow
              key={s}
              label={severityLabel(s)}
              tone={s}
              value={FINDINGS_BY_SEVERITY[s]}
              max={findingMax}
            />
          ))}
        </Panel>
        <Panel title="Paths by level">
          {ATTACK_LEVELS.map((l) => (
            <BarRow
              key={l}
              label={severityLabel(levelTone(l))}
              tone={levelTone(l)}
              value={PATHS_BY_LEVEL[l]}
              max={levelMax}
            />
          ))}
          <BarRow label="No tone" value={9} max={levelMax} />
          <BarRow label="An unusually long label that truncates" value={0} max={levelMax} />
        </Panel>
      </div>
      <Panel title="Ranked paths">
        <ul className="flex flex-col divide-y">
          {PATHS.map((p, i) => (
            <li
              key={p.id}
              className="grid grid-cols-[1.5rem_4.5rem_5.5rem_minmax(0,1fr)_14rem] items-center gap-3 py-2 text-dense first:pt-0 last:pb-0"
            >
              <span className="text-right text-muted-foreground tabular-nums">{i + 1}</span>
              <span className="font-mono text-xs font-medium">{p.id}</span>
              <span>
                <LevelBadge level={p.level} />
              </span>
              <span className="min-w-0 truncate">
                <span className="text-foreground">{p.objective}</span>
                <span className="text-muted-foreground"> · {chainText(p.hops)}</span>
              </span>
              <ScoreBar score={p.score} max={top} level={p.level} markers={[30, 40]} />
            </li>
          ))}
        </ul>
      </Panel>
    </Section>
  )
}

function ChainSection() {
  const [selected, setSelected] = useState<string | null>(null)
  return (
    <Section
      id="chains"
      title="Chain diagram"
      description="A path as resource boxes in the graph's colours. Dashed border marks the entry. Wraps at any width; arrows stay attached to the box before them."
    >
      <Panel title="AP-001, 5 hops, with technique labels">
        <ChainDiagram nodes={AP_001} edgeLabels={AP_001_TECHNIQUES} />
      </Panel>
      <Panel title="AP-007, 7 hops, clickable (opens the resource sheet in the app)">
        <ChainDiagram nodes={AP_007} onNodeSelect={setSelected} />
        <p className="mt-3 text-xs text-muted-foreground" aria-live="polite">
          {selected ? (
            <>
              Selected <span className="font-mono text-foreground">{selected}</span>
            </>
          ) : (
            'Click or press Enter on a box.'
          )}
        </p>
      </Panel>
      <div className="grid grid-cols-[minmax(0,26rem)_minmax(0,1fr)] gap-3">
        <Panel title="7 hops, long ids, 26rem wide">
          <ChainDiagram nodes={LONG_IDS} />
        </Panel>
        <Panel title="Compact, for cards and rows">
          <div className="flex flex-col gap-3">
            <ChainDiagram nodes={AP_001} size="compact" />
            <ChainDiagram nodes={AP_007} size="compact" />
            <ChainDiagram
              nodes={chain(['OpenSecurityGroup', 'PublicEC2Instance'])}
              size="compact"
            />
          </div>
        </Panel>
      </div>
    </Section>
  )
}

function TableSection() {
  return (
    <Section
      id="table"
      title="Dense table"
      description="13px text, 36px rows, 12px muted headers, hairline dividers. Ids in mono, numbers tabular and right-aligned."
    >
      <div className="overflow-hidden rounded-lg border bg-surface">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-28">Severity</TableHead>
              <TableHead>Resource</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Finding</TableHead>
              <TableHead>Semantic</TableHead>
              <TableHead>ATT&amp;CK</TableHead>
              <TableHead className="text-right">On paths</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {FINDINGS.map((f) => (
              <TableRow key={`${f.resource}-${f.finding}`} className="cursor-pointer">
                <TableCell>
                  <SeverityBadge severity={f.severity} variant="dot" />
                </TableCell>
                <TableCell className="font-mono text-xs">{f.resource}</TableCell>
                <TableCell className="text-muted-foreground">{f.type}</TableCell>
                <TableCell>{f.finding}</TableCell>
                <TableCell className="text-muted-foreground">{f.semantic}</TableCell>
                <TableCell>
                  {f.techniques.length > 0 ? (
                    <span className="flex gap-1">
                      {f.techniques.map((t) => (
                        <TechniqueChip key={t} id={t} />
                      ))}
                    </span>
                  ) : (
                    <span className="text-muted-foreground">-</span>
                  )}
                </TableCell>
                <TableCell className={`text-right ${f.paths === 0 ? 'text-muted-foreground' : ''}`}>
                  {formatCount(f.paths)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </Section>
  )
}

function TabsSection() {
  return (
    <Section id="tabs" title="Tabs">
      <Panel>
        <div className="flex flex-col gap-6">
          <Tabs defaultValue="state">
            <TabsList aria-label="Graph view">
              <TabsTrigger value="state">State graph</TabsTrigger>
              <TabsTrigger value="attack">Attack graph</TabsTrigger>
            </TabsList>
            <TabsContent value="state" className="pt-3 text-dense text-muted-foreground">
              Segmented control, for switching a view in place.
            </TabsContent>
            <TabsContent value="attack" className="pt-3 text-dense text-muted-foreground">
              The attack graph view.
            </TabsContent>
          </Tabs>
          <Tabs defaultValue="findings">
            <div className="border-b">
              <TabsList variant="line" aria-label="Resource">
                <TabsTrigger value="findings">Findings</TabsTrigger>
                <TabsTrigger value="attributes">Attributes</TabsTrigger>
                <TabsTrigger value="paths">Paths</TabsTrigger>
              </TabsList>
            </div>
            <TabsContent value="findings" className="pt-3 text-dense text-muted-foreground">
              Line tabs, for navigation between sections.
            </TabsContent>
            <TabsContent value="attributes" className="pt-3 text-dense text-muted-foreground">
              Attributes.
            </TabsContent>
            <TabsContent value="paths" className="pt-3 text-dense text-muted-foreground">
              Paths.
            </TabsContent>
          </Tabs>
        </div>
      </Panel>
    </Section>
  )
}

function OverlaySection() {
  return (
    <Section id="overlays" title="Overlays" description="The only elements with a shadow.">
      <Panel>
        <div className="flex flex-wrap items-center gap-2">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="outline" disabled={false}>
                Tooltip
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              Scenarios are generated only for paths at or above the minimum level
            </TooltipContent>
          </Tooltip>

          <Popover>
            <PopoverTrigger asChild>
              <Button variant="outline">Score breakdown</Button>
            </PopoverTrigger>
            <PopoverContent align="start" className="w-80">
              <PopoverHeader>
                <PopoverTitle>Score 56.04</PopoverTitle>
                <PopoverDescription>How AP-001 was scored</PopoverDescription>
              </PopoverHeader>
              <dl className="grid grid-cols-[1fr_auto] gap-x-4 gap-y-1 text-dense tabular-nums">
                <dt className="text-muted-foreground">Finding weights</dt>
                <dd className="text-right">68.00</dd>
                <dt className="text-muted-foreground">Objective weight</dt>
                <dd className="text-right">5.00</dd>
                <dt className="text-muted-foreground">Length factor, 4 hops</dt>
                <dd className="text-right">× {formatFactor(0.85 ** 3)}</dd>
                <dt className="text-muted-foreground">Public entry</dt>
                <dd className="text-right">× 1.25</dd>
                <dt className="border-t pt-1 font-medium">Score</dt>
                <dd className="border-t pt-1 text-right font-medium">56.04</dd>
              </dl>
              <p className="font-mono text-2xs text-muted-foreground">
                (68 + 5) × 0.85^3 × 1.25 = 56.04, Critical at 40 and above
              </p>
            </PopoverContent>
          </Popover>

          <Dialog>
            <DialogTrigger asChild>
              <Button variant="outline">Dialog</Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Generate a scenario for AP-001?</DialogTitle>
                <DialogDescription>
                  Live generation uses GPU quota on the model Space. Cached scenarios stay available
                  either way.
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button variant="outline">Cancel</Button>
                <Button>Generate</Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Sheet>
            <SheetTrigger asChild>
              <Button variant="outline">Sheet</Button>
            </SheetTrigger>
            <SheetContent>
              <SheetHeader>
                <SheetTitle className="font-mono">OverPermissiveRole</SheetTitle>
                <SheetDescription>IAM Role · 3 findings · on 14 paths</SheetDescription>
              </SheetHeader>
              <div className="flex flex-col gap-3 p-5">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity="critical" />
                  <span className="text-sm font-medium">Creating a new policy version</span>
                </div>
                <p className="text-dense text-muted-foreground">
                  The role can create a new version of a managed policy attached to it and set it as
                  default, granting itself any permission.
                </p>
              </div>
            </SheetContent>
          </Sheet>
        </div>
      </Panel>
    </Section>
  )
}

function StatesSection() {
  return (
    <Section id="states" title="Empty, error, loading">
      <div className="grid grid-cols-2 gap-3">
        <EmptyState
          bordered
          icon={Inbox}
          title="No attack paths"
          description="No route reaches an objective from an entry point. Findings are still listed."
          action={
            <Button variant="outline" size="sm">
              View findings
            </Button>
          }
        />
        <ErrorState
          title="Could not load this analysis"
          message="Analysis 3f2c9a1e-0b7d-4a51-9c3e-5d8f1a2b6c40 was not found."
          onRetry={() => undefined}
        />
      </div>
      <ErrorState
        variant="inline"
        title="Scenario generation failed"
        message="The model Space did not answer within 120 s. Cached scenarios are unaffected."
        onRetry={() => undefined}
      />
      <ErrorState
        variant="inline"
        title="Upload rejected"
        message="Template has 612 resources. The limit is 500."
      />
      <div className="grid grid-cols-2 gap-3">
        <TableSkeleton rows={5} columns={5} />
        <CardListSkeleton count={2} />
      </div>
      <Panel>
        <AnalysisHeaderSkeleton />
      </Panel>
    </Section>
  )
}

function LayoutSection() {
  const [tab, setTab] = useState<AnalysisTab>('overview')
  return (
    <Section
      id="layout"
      title="Analysis layout"
      description="Header band, meta line, report action and URL-bound tabs. Shown here in a frame."
    >
      <div className="overflow-hidden rounded-lg border bg-background">
        <AnalysisLayout
          title="cloudformation5.yml"
          meta={
            <>
              <span>Information technology service activities (ISIC J62)</span>
              <MetaDot />
              <span>
                Minimum level <span className="text-foreground">High</span>
              </span>
              <MetaDot />
              <span>{formatDateTime('2026-10-24T10:28:00Z')}</span>
              <MetaDot />
              <span className="font-mono text-xs">sha256 9c1f2ab</span>
            </>
          }
          actions={
            <Button variant="outline">
              <Download />
              Download report
            </Button>
          }
          tab={tab}
          onTabChange={setTab}
          tabCounts={{ findings: 22, paths: 22 }}
        >
          <div className="grid grid-cols-5 gap-3">
            <StatTile label="Resources" value={15} />
            <StatTile label="Findings" value={22} />
            <StatTile label="Attack paths" value={22} />
            <StatTile label="Entry points" value={7} />
            <StatTile label="Top score" value="56.04" tone="critical" />
          </div>
        </AnalysisLayout>
      </div>
    </Section>
  )
}
