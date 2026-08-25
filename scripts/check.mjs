import { access, readFile } from 'node:fs/promises'
const required = ['.codex-plugin/plugin.json', '.mcp.json', 'mcp-server.mjs', 'bin/dsh-retention-settlement-proof.mjs', 'cordis.patch.yml', 'index.js', 'lib/retention-settlement-proof.mjs', 'README.md', 'README.zh-CN.md', 'SECURITY.md']
await Promise.all(required.map(file => access(file))); const pkg = JSON.parse(await readFile('package.json', 'utf8')); const plugin = JSON.parse(await readFile('.codex-plugin/plugin.json', 'utf8')); const mcp = JSON.parse(await readFile('.mcp.json', 'utf8')); const entry = await readFile('index.js', 'utf8'); const core = await readFile('lib/retention-settlement-proof.mjs', 'utf8')
if (pkg.name !== plugin.name || pkg.version !== plugin.version || plugin.mcpServers !== './.mcp.json' || !mcp.mcpServers?.['dsh-retention-settlement-proof']) throw new Error('identity or MCP mismatch')
if (pkg.scripts?.preinstall || pkg.scripts?.install || pkg.scripts?.postinstall || pkg.scripts?.prepare) throw new Error('lifecycle scripts forbidden')
if (/export\s+default\b/.test(entry) || entry.includes('@deepseek-ai/dsh-tools')) throw new Error('entry must be namespace-loader safe and host-neutral')
for (const guard of ['regular non-symlink file', 'verifiedByReadBack', 'resurrectionDetected', 'returnsReceiptBodies', 'destructiveActions', 'UNSAFE_ARTIFACT_DIR']) if (!core.includes(guard)) throw new Error(`guard missing: ${guard}`)
process.stdout.write(`${JSON.stringify({ ok: true, requiredFiles: required.length, lifecycleScripts: false, mcp: true, namespaceLoaderSafe: true, destructiveActions: false })}\n`)
