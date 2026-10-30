/**
 * Named aliases for the generated API types. src/api/schema.d.ts is written by
 * `npm run types` from app/api/tests/fixtures/openapi.json; never edit it by
 * hand. Import API shapes from here so call sites read `Meta`, not
 * `components['schemas']['Meta']`.
 */

import type { components } from './schema'

type Schemas = components['schemas']

export type Meta = Schemas['Meta']
export type Sample = Schemas['Sample']
export type SampleKind = Sample['kind']
export type Limits = Schemas['Limits']
export type ObjectiveMeta = Schemas['ObjectiveMeta']
export type SampleRequest = Schemas['SampleRequest']
export type Health = Schemas['Health']

export type Analysis = Schemas['Analysis']
export type Summary = Schemas['Summary']
export type Finding = Schemas['Finding']
export type Resource = Schemas['Resource']
export type Path = Schemas['Path']
export type Step = Schemas['Step']
export type ScoreBreakdown = Schemas['ScoreBreakdown']
export type PathRisk = Schemas['PathRisk']
export type Reachability = PathRisk['reachability']
export type FixImpact = Schemas['FixImpact']
export type FixImpactResult = Schemas['FixImpactResult']
export type AnalysisWarning = Schemas['Warning']
export type GraphView = Schemas['GraphView']
export type GraphNode = Schemas['GraphNode']
export type GraphEdge = Schemas['GraphEdge']
export type ScenarioState = Schemas['ScenarioState']
export type Scenario = Schemas['Scenario']
