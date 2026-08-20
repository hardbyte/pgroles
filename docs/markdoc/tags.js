import { Callout } from '@/components/Callout'
import { OperatorArchitectureDiagram } from '@/components/OperatorArchitectureDiagram'
import { OperatorReconciliationDiagram } from '@/components/OperatorReconciliationDiagram'
import { PostgresPermissionLab } from '@/components/PostgresPermissionLab'
import { QuickLink, QuickLinks } from '@/components/QuickLinks'
import { RoleGraphDiagram } from '@/components/RoleGraphDiagram'
import { WorkspaceDataFlowDiagram } from '@/components/WorkspaceDataFlowDiagram'

const tags = {
  callout: {
    attributes: {
      title: { type: String },
      type: {
        type: String,
        default: 'note',
        matches: ['note', 'warning', 'beginner'],
        errorLevel: 'critical',
      },
    },
    render: Callout,
  },
  figure: {
    selfClosing: true,
    attributes: {
      src: { type: String },
      alt: { type: String },
      caption: { type: String },
    },
    render: ({ src, alt = '', caption }) => (
      <figure>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={src} alt={alt} />
        <figcaption>{caption}</figcaption>
      </figure>
    ),
  },
  'quick-links': {
    render: QuickLinks,
  },
  'quick-link': {
    selfClosing: true,
    render: QuickLink,
    attributes: {
      title: { type: String },
      description: { type: String },
      icon: { type: String },
      href: { type: String },
    },
  },
  'operator-architecture-diagram': {
    selfClosing: true,
    render: OperatorArchitectureDiagram,
  },
  'operator-reconciliation-diagram': {
    selfClosing: true,
    render: OperatorReconciliationDiagram,
  },
  'postgres-permission-lab': {
    selfClosing: true,
    render: PostgresPermissionLab,
  },
  'role-graph-diagram': {
    selfClosing: true,
    render: RoleGraphDiagram,
  },
  'workspace-data-flow-diagram': {
    selfClosing: true,
    render: WorkspaceDataFlowDiagram,
  }
}

export default tags
