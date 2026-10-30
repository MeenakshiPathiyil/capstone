// The cloudformation5 sample's ranked paths, reduced to what highlighting reads. Test data only.
import type { Path, Step } from '@/api/types'

export type FixturePath = Pick<Path, 'source_id' | 'rank' | 'exported'> & {
  steps: Pick<Step, 'source' | 'target' | 'action_id'>[]
}

export const samplePaths: FixturePath[] = [
  {
    source_id: 'AP-001',
    rank: 1,
    exported: true,
    steps: [
      {
        source: 'OpenSecurityGroup',
        target: 'PublicEC2Instance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'PublicEC2Instance',
        target: 'OverPermissiveInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'OverPermissiveInstanceProfile',
        target: 'OverPermissiveRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'OverPermissiveRole',
        target: 'InsecureS3Bucket',
        action_id: 'ACT_READ_CLOUD_STORAGE',
      },
    ],
  },
  {
    source_id: 'AP-002',
    rank: 2,
    exported: true,
    steps: [
      {
        source: 'OpenSecurityGroup',
        target: 'PublicEC2Instance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'PublicEC2Instance',
        target: 'OverPermissiveInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'OverPermissiveInstanceProfile',
        target: 'OverPermissiveRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'OverPermissiveRole',
        target: 'InsecureS3Bucket',
        action_id: 'ACT_READ_CLOUD_STORAGE',
      },
    ],
  },
  {
    source_id: 'AP-003',
    rank: 3,
    exported: true,
    steps: [
      {
        source: 'OpenSecurityGroup',
        target: 'PublicEC2Instance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'PublicEC2Instance',
        target: 'OverPermissiveInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'OverPermissiveInstanceProfile',
        target: 'OverPermissiveRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'OverPermissiveRole',
        target: 'PublicRDS',
        action_id: 'ACT_QUERY_DATA_STORE',
      },
    ],
  },
  {
    source_id: 'AP-004',
    rank: 4,
    exported: true,
    steps: [
      {
        source: 'OpenSecurityGroup',
        target: 'PublicEC2Instance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'PublicEC2Instance',
        target: 'OverPermissiveInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'OverPermissiveInstanceProfile',
        target: 'OverPermissiveRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'OverPermissiveRole',
        target: 'PublicRDS',
        action_id: 'ACT_QUERY_DATA_STORE',
      },
    ],
  },
  {
    source_id: 'AP-005',
    rank: 5,
    exported: true,
    steps: [
      {
        source: 'OpenSecurityGroup',
        target: 'PublicEC2Instance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'PublicEC2Instance',
        target: 'OverPermissiveInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'OverPermissiveInstanceProfile',
        target: 'OverPermissiveRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'OverPermissiveRole',
        target: 'PublicRDS',
        action_id: 'ACT_QUERY_DATA_STORE',
      },
    ],
  },
  {
    source_id: 'AP-006',
    rank: 6,
    exported: true,
    steps: [
      {
        source: 'OpenSecurityGroup',
        target: 'PublicEC2Instance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'PublicEC2Instance',
        target: 'OverPermissiveInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'OverPermissiveInstanceProfile',
        target: 'OverPermissiveRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
    ],
  },
  {
    source_id: 'AP-007',
    rank: 7,
    exported: true,
    steps: [
      {
        source: 'AppSecurityGroup',
        target: 'AppServerInstance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'AppServerInstance',
        target: 'AppInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'AppInstanceProfile',
        target: 'AppServerRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'AppServerRole',
        target: 'DeploymentRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'DeploymentRole',
        target: 'OverPermissiveRole',
        action_id: 'ACT_WRITE_ROLE_POLICY',
      },
      {
        source: 'OverPermissiveRole',
        target: 'InsecureS3Bucket',
        action_id: 'ACT_READ_CLOUD_STORAGE',
      },
    ],
  },
  {
    source_id: 'AP-008',
    rank: 8,
    exported: true,
    steps: [
      {
        source: 'AppSecurityGroup',
        target: 'AppServerInstance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'AppServerInstance',
        target: 'AppInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'AppInstanceProfile',
        target: 'AppServerRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'AppServerRole',
        target: 'DeploymentRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'DeploymentRole',
        target: 'OverPermissiveRole',
        action_id: 'ACT_WRITE_ROLE_POLICY',
      },
      {
        source: 'OverPermissiveRole',
        target: 'InsecureS3Bucket',
        action_id: 'ACT_READ_CLOUD_STORAGE',
      },
    ],
  },
  {
    source_id: 'AP-009',
    rank: 9,
    exported: true,
    steps: [
      {
        source: 'AppSecurityGroup',
        target: 'AppServerInstance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'AppServerInstance',
        target: 'AppInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'AppInstanceProfile',
        target: 'AppServerRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'AppServerRole',
        target: 'DeploymentRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'DeploymentRole',
        target: 'OverPermissiveRole',
        action_id: 'ACT_WRITE_ROLE_POLICY',
      },
      {
        source: 'OverPermissiveRole',
        target: 'PublicRDS',
        action_id: 'ACT_QUERY_DATA_STORE',
      },
    ],
  },
  {
    source_id: 'AP-010',
    rank: 10,
    exported: true,
    steps: [
      {
        source: 'AppSecurityGroup',
        target: 'AppServerInstance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'AppServerInstance',
        target: 'AppInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'AppInstanceProfile',
        target: 'AppServerRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'AppServerRole',
        target: 'DeploymentRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'DeploymentRole',
        target: 'OverPermissiveRole',
        action_id: 'ACT_WRITE_ROLE_POLICY',
      },
      {
        source: 'OverPermissiveRole',
        target: 'PublicRDS',
        action_id: 'ACT_QUERY_DATA_STORE',
      },
    ],
  },
  {
    source_id: 'AP-011',
    rank: 11,
    exported: true,
    steps: [
      {
        source: 'OpenSecurityGroup',
        target: 'PublicEC2Instance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'PublicEC2Instance',
        target: 'OverPermissiveInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'OverPermissiveInstanceProfile',
        target: 'OverPermissiveRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'OverPermissiveRole',
        target: 'ReportsTable',
        action_id: 'ACT_QUERY_DATA_STORE',
      },
    ],
  },
  {
    source_id: 'AP-012',
    rank: 12,
    exported: true,
    steps: [
      {
        source: 'OpenSecurityGroup',
        target: 'PublicEC2Instance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'PublicEC2Instance',
        target: 'OverPermissiveInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'OverPermissiveInstanceProfile',
        target: 'OverPermissiveRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'OverPermissiveRole',
        target: 'ReportsTable',
        action_id: 'ACT_QUERY_DATA_STORE',
      },
    ],
  },
  {
    source_id: 'AP-013',
    rank: 13,
    exported: true,
    steps: [
      {
        source: 'AppSecurityGroup',
        target: 'AppServerInstance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'AppServerInstance',
        target: 'AppInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'AppInstanceProfile',
        target: 'AppServerRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'AppServerRole',
        target: 'DeploymentRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'DeploymentRole',
        target: 'OverPermissiveRole',
        action_id: 'ACT_WRITE_ROLE_POLICY',
      },
      {
        source: 'OverPermissiveRole',
        target: 'PublicRDS',
        action_id: 'ACT_QUERY_DATA_STORE',
      },
    ],
  },
  {
    source_id: 'AP-014',
    rank: 14,
    exported: true,
    steps: [
      {
        source: 'AppSecurityGroup',
        target: 'AppServerInstance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'AppServerInstance',
        target: 'AppInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'AppInstanceProfile',
        target: 'AppServerRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'AppServerRole',
        target: 'DeploymentRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'DeploymentRole',
        target: 'OverPermissiveRole',
        action_id: 'ACT_WRITE_ROLE_POLICY',
      },
    ],
  },
  {
    source_id: 'AP-015',
    rank: 15,
    exported: true,
    steps: [
      {
        source: 'OpenSecurityGroup',
        target: 'PublicEC2Instance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
    ],
  },
  {
    source_id: 'AP-016',
    rank: 16,
    exported: true,
    steps: [
      {
        source: 'AppSecurityGroup',
        target: 'AppServerInstance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'AppServerInstance',
        target: 'AppInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'AppInstanceProfile',
        target: 'AppServerRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'AppServerRole',
        target: 'DeploymentRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'DeploymentRole',
        target: 'OverPermissiveRole',
        action_id: 'ACT_WRITE_ROLE_POLICY',
      },
      {
        source: 'OverPermissiveRole',
        target: 'ReportsTable',
        action_id: 'ACT_QUERY_DATA_STORE',
      },
    ],
  },
  {
    source_id: 'AP-017',
    rank: 17,
    exported: true,
    steps: [
      {
        source: 'AppSecurityGroup',
        target: 'AppServerInstance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'AppServerInstance',
        target: 'AppInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'AppInstanceProfile',
        target: 'AppServerRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'AppServerRole',
        target: 'DeploymentRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'DeploymentRole',
        target: 'OverPermissiveRole',
        action_id: 'ACT_WRITE_ROLE_POLICY',
      },
      {
        source: 'OverPermissiveRole',
        target: 'ReportsTable',
        action_id: 'ACT_QUERY_DATA_STORE',
      },
    ],
  },
  {
    source_id: 'AP-018',
    rank: 18,
    exported: true,
    steps: [
      {
        source: 'AppSecurityGroup',
        target: 'AppServerInstance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'AppServerInstance',
        target: 'AppInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'AppInstanceProfile',
        target: 'AppServerRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'AppServerRole',
        target: 'DeploymentRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
    ],
  },
  {
    source_id: 'AP-019',
    rank: 19,
    exported: true,
    steps: [
      {
        source: 'AppSecurityGroup',
        target: 'AppServerInstance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
    ],
  },
  {
    source_id: 'AP-020',
    rank: 20,
    exported: false,
    steps: [
      {
        source: 'AppSecurityGroup',
        target: 'AppServerInstance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'AppServerInstance',
        target: 'AppInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'AppInstanceProfile',
        target: 'AppServerRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
    ],
  },
  {
    source_id: 'AP-021',
    rank: 21,
    exported: false,
    steps: [
      {
        source: 'AppSecurityGroup',
        target: 'AppServerInstance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'AppServerInstance',
        target: 'AppInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'AppInstanceProfile',
        target: 'AppServerRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'AppServerRole',
        target: 'DeploymentRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'DeploymentRole',
        target: 'ReportsTable',
        action_id: 'ACT_QUERY_DATA_STORE',
      },
    ],
  },
  {
    source_id: 'AP-022',
    rank: 22,
    exported: false,
    steps: [
      {
        source: 'AppSecurityGroup',
        target: 'AppServerInstance',
        action_id: 'ACT_REACH_EXPOSED_ADMIN_SERVICE',
      },
      {
        source: 'AppServerInstance',
        target: 'AppInstanceProfile',
        action_id: 'ACT_READ_INSTANCE_METADATA',
      },
      {
        source: 'AppInstanceProfile',
        target: 'AppServerRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'AppServerRole',
        target: 'DeploymentRole',
        action_id: 'ACT_USE_ATTACHED_IDENTITY',
      },
      {
        source: 'DeploymentRole',
        target: 'ReportsTable',
        action_id: 'ACT_QUERY_DATA_STORE',
      },
    ],
  },
]
