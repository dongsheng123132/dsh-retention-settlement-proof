# dsh-retention-settlement-proof

Offline, body-free evidence that a recorded DeepSeek Harness retention/deletion request settled across required storage projections and stayed absent after restart.

This plugin **does not delete anything**. DSH session persistence currently has no general delete/retention API, while community archive/delete plugins implement different mutation strategies. This proof layer consumes explicit, pre-recorded receipts from those implementations or test harnesses. It is complementary to `dsh-recovery-proof` (restore drills), `dsh-decision-effect-proof` (authorization/effect reconciliation), and deletion UIs: it answers only whether one opaque subject remained absent across declared surfaces and restart epochs.

## Evidence contract

Schema version 1 binds:

- a SHA-256 pseudonymous subject (never a raw session ID);
- a deletion request with an opaque approval-receipt hash;
- a tombstone bound to the exact request bytes;
- body-free absence observations for explicit surfaces such as `persistence-list`, `session-index`, and `workspace-index`;
- fixed evaluation time, freshness limit, required surfaces, and minimum complete post-restart epochs.

Any later `present: true`, stale receipt, missing surface, pre-restart-only evidence, identity mismatch, digest mismatch, unsafe path, or incomplete threshold fails closed. The report contains hashes and verdicts only—not session text, receipt bodies, filesystem paths, credentials, or secrets.

## CLI

```bash
dsh-retention-settlement-proof inspect --workspace . --manifest proof.json
dsh-retention-settlement-proof verify --workspace . --manifest proof.json --artifactDir artifacts
```

Verification reads only workspace-relative regular files, rejects symlinks and traversal, performs no network requests or subprocesses, and writes only one content-addressed JSON report beneath the explicit artifact directory with exclusive creation and read-back verification. Exit code 0 means `verified-absent`, 2 means a policy rejection, and 1 means invalid/unsafe input.

## DSH and MCP

The DSH bundle exposes `dsh_retention_settlement_inspect` and `dsh_retention_settlement_verify`. The independent stdio MCP server exposes proof-only inline equivalents and never accesses the filesystem. Both call the same interface-free core.

```bash
npm test
npm run check
npm run smoke:plugin
npm run smoke:mcp
python C:/Users/ZhuanZ/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
```

MIT licensed. See [SECURITY.md](SECURITY.md).
