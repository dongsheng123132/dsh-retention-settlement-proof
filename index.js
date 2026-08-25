import { inspectRetentionManifestJson, verifyRetentionSettlement } from './lib/retention-settlement-proof.mjs'
export const name = 'dsh-retention-settlement-proof'
export const inject = ['tools']
const renderJson = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }]
const define = value => ({ ...value, output: { schema: {}, render: renderJson } })
export function createDefinitions(_ctx = {}, config = {}) { const workspaceRoot = config.workspaceRoot || process.cwd(); return [
  define({ name: 'dsh_retention_settlement_inspect', description: 'Inspect a retention settlement manifest without reading receipt bodies.', parameters: { type: 'object', required: ['manifestJson'], properties: { manifestJson: { type: 'string' } }, additionalProperties: false }, execute: async ({ manifestJson }) => inspectRetentionManifestJson(manifestJson) }),
  define({ name: 'dsh_retention_settlement_verify', description: 'Verify recorded absence across required DSH surfaces and post-restart epochs without deleting anything.', parameters: { type: 'object', required: ['manifestPath', 'artifactDir'], properties: { manifestPath: { type: 'string' }, artifactDir: { type: 'string' } }, additionalProperties: false }, execute: async args => verifyRetentionSettlement({ workspaceRoot, ...args }) })
] }
export function apply(ctx, config = {}) { for (const definition of createDefinitions(ctx, config)) ctx.tools.register(definition) }
