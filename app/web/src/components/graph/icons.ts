import {
  CircleSmall,
  Database,
  Globe,
  KeyRound,
  SquareTerminal,
  type LucideIcon,
} from 'lucide-react'

import type { FactKind } from './labels'

/** One icon per kind of fact an attacker can hold. The legend shows the same set. */
export const FACT_ICONS: Record<FactKind, LucideIcon> = {
  foothold: SquareTerminal,
  credential: KeyRound,
  data_access: Database,
  internet_reachable: Globe,
  other: CircleSmall,
}
