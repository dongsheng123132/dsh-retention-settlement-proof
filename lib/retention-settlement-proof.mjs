import { createHash } from 'node:crypto'
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises'
import { isAbsolute, relative, resolve } from 'node:path'

const MAX_FILE = 1024 * 1024
const HEX = /^[a-f0-9]{64}$/
const sha = value => createHash('sha256').update(value).digest('hex')
const stable = value => JSON.stringify(value, (_, v) => v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b))) : v)
const fail = (code, message) => Object.assign(new Error(message), { code })
const secretField = value => value && typeof value === 'object' && Object.entries(value).some(([key, child]) => /(?:secret|password|credential|api[_-]?key|private[_-]?key|token)$/i.test(key) || secretField(child))
const bounded = (value, label, max = 256) => { if (typeof value !== 'string' || !value || value.length > max) throw fail('INVALID_MANIFEST', `${label} must be a non-empty bounded string`) }
const hash = (value, label) => { if (!HEX.test(value)) throw fail('INVALID_MANIFEST', `${label} must be lowercase SHA-256`) }
const time = (value, label) => { const n = Date.parse(value); if (!Number.isFinite(n)) throw fail('INVALID_TIME', `${label} must be an ISO timestamp`); return n }

function parseManifest(input) {
  let m; try { m = typeof input === 'string' ? JSON.parse(input) : input } catch { throw fail('INVALID_MANIFEST', 'manifest must be JSON') }
  if (!m || m.schemaVersion !== 1 || secretField(m)) throw fail('INVALID_MANIFEST', 'schemaVersion 1 required and secret-shaped fields are forbidden')
  bounded(m.proofId, 'proofId'); hash(m.subjectHash, 'subjectHash'); time(m.evaluationTime, 'evaluationTime')
  for (const [label, item] of [['request', m.request], ['tombstone', m.tombstone]]) { bounded(item?.path, `${label}.path`, 512); hash(item?.sha256, `${label}.sha256`) }
  if (!Array.isArray(m.observations) || !m.observations.length || m.observations.length > 128) throw fail('INVALID_MANIFEST', '1..128 observations required')
  for (const item of m.observations) { bounded(item.id, 'observation.id'); bounded(item.path, 'observation.path', 512); hash(item.sha256, 'observation.sha256') }
  const surfaces = m.policy?.requiredSurfaces
  if (!Array.isArray(surfaces) || !surfaces.length || surfaces.length > 16 || new Set(surfaces).size !== surfaces.length) throw fail('INVALID_MANIFEST', 'unique requiredSurfaces required')
  for (const surface of surfaces) bounded(surface, 'requiredSurface')
  if (!Number.isInteger(m.policy.minPostRestartEpochs) || m.policy.minPostRestartEpochs < 1 || m.policy.minPostRestartEpochs > 16) throw fail('INVALID_MANIFEST', 'minPostRestartEpochs must be 1..16')
  if (!Number.isInteger(m.policy.maxEvidenceAgeMs) || m.policy.maxEvidenceAgeMs < 1000 || m.policy.maxEvidenceAgeMs > 365 * 86400000) throw fail('INVALID_MANIFEST', 'maxEvidenceAgeMs is out of range')
  return m
}

async function safeFile(root, path, expected) {
  bounded(path, 'path', 512); if (isAbsolute(path)) throw fail('PATH_ESCAPE', 'paths must be workspace-relative')
  const absolute = resolve(root, path); const rel = relative(root, absolute); if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'path escapes workspaceRoot')
  let stat; try { stat = await lstat(absolute) } catch { throw fail('MISSING_EVIDENCE', `missing evidence: ${path}`) }
  if (stat.isSymbolicLink() || !stat.isFile()) throw fail('UNSAFE_FILE', 'evidence must be a regular non-symlink file')
  if (stat.size > MAX_FILE) throw fail('FILE_TOO_LARGE', 'evidence exceeds 1 MiB')
  const rootReal = await realpath(root); const real = await realpath(absolute); const realRel = relative(rootReal, real); if (realRel.startsWith('..') || isAbsolute(realRel)) throw fail('PATH_ESCAPE', 'real path escapes workspaceRoot')
  const bytes = await readFile(real); if (expected && sha(bytes) !== expected) throw fail('DIGEST_MISMATCH', `digest mismatch: ${path}`); return bytes
}

async function safeArtifactDir(root, path) {
  bounded(path, 'artifactDir', 512); if (isAbsolute(path)) throw fail('PATH_ESCAPE', 'artifactDir must be workspace-relative')
  const dir = resolve(root, path); const rel = relative(root, dir); if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'artifactDir escapes workspaceRoot')
  let cursor = root; for (const part of rel.split(/[\\/]/)) { cursor = resolve(cursor, part); try { const stat = await lstat(cursor); if (stat.isSymbolicLink() || !stat.isDirectory()) throw fail('UNSAFE_ARTIFACT_DIR', 'artifactDir components must be real directories') } catch (error) { if (error.code !== 'ENOENT') throw error; await mkdir(cursor) } }
  return dir
}

function parseReceipt(bytes, expectedKind) {
  let value; try { value = JSON.parse(bytes) } catch { throw fail('INVALID_RECEIPT', 'receipt must be JSON') }
  if (!value || value.schemaVersion !== 1 || value.kind !== expectedKind || secretField(value)) throw fail('INVALID_RECEIPT', `expected ${expectedKind} without secret-shaped fields`)
  return value
}

export function inspectRetentionManifestJson(manifestJson) {
  const m = parseManifest(manifestJson)
  return { schemaVersion: 1, proofId: m.proofId, subjectHash: m.subjectHash, observationCount: m.observations.length, requiredSurfaces: [...m.policy.requiredSurfaces].sort(), minPostRestartEpochs: m.policy.minPostRestartEpochs, filesystemAccess: false, destructiveActions: false, returnsReceiptBodies: false }
}

export function evaluateRetentionSettlement({ manifestJson, requestJson, tombstoneJson, observationsJson }) {
  const m = parseManifest(manifestJson); const requestBytes = Buffer.from(requestJson); const tombstoneBytes = Buffer.from(tombstoneJson); const request = parseReceipt(requestBytes, 'deletion-request'); const tombstone = parseReceipt(tombstoneBytes, 'deletion-tombstone')
  const observationsInput = typeof observationsJson === 'string' ? JSON.parse(observationsJson) : observationsJson
  if (!Array.isArray(observationsInput) || observationsInput.length !== m.observations.length) throw fail('MISSING_EVIDENCE', 'observation count does not match manifest')
  const evaluationMs = time(m.evaluationTime, 'evaluationTime'); const requestedMs = time(request.requestedAt, 'requestedAt'); const settledMs = time(tombstone.settledAt, 'settledAt')
  const identityMatched = request.subjectHash === m.subjectHash && tombstone.subjectHash === m.subjectHash && request.deletionId === tombstone.deletionId
  const requestBound = tombstone.requestSha256 === m.request.sha256 && sha(requestBytes) === m.request.sha256 && sha(tombstoneBytes) === m.tombstone.sha256
  const approvalBound = HEX.test(request.approvalReceiptSha256 || '')
  const chronologyValid = settledMs >= requestedMs && settledMs <= evaluationMs
  const rows = []; const coverage = new Map(); let resurrectionDetected = false
  for (let index = 0; index < observationsInput.length; index++) {
    const bytes = Buffer.from(typeof observationsInput[index] === 'string' ? observationsInput[index] : stable(observationsInput[index])); const receipt = parseReceipt(bytes, 'absence-observation'); const spec = m.observations[index]; const observedMs = time(receipt.observedAt, 'observedAt'); const digestMatched = sha(bytes) === spec.sha256
    const matched = receipt.subjectHash === m.subjectHash && receipt.deletionId === request.deletionId; const fresh = observedMs >= settledMs && observedMs <= evaluationMs && evaluationMs - observedMs <= m.policy.maxEvidenceAgeMs; const postRestart = Number.isInteger(receipt.epoch) && receipt.epoch > 0; const absent = receipt.present === false; if (receipt.present === true && observedMs >= settledMs) resurrectionDetected = true
    if (matched && fresh && postRestart && absent && digestMatched && m.policy.requiredSurfaces.includes(receipt.surface) && HEX.test(receipt.sourceSnapshotSha256 || '')) { if (!coverage.has(receipt.epoch)) coverage.set(receipt.epoch, new Set()); coverage.get(receipt.epoch).add(receipt.surface) }
    rows.push({ id: spec.id, sha256: sha(bytes), surface: receipt.surface || null, epoch: Number.isInteger(receipt.epoch) ? receipt.epoch : null, digestMatched, identityMatched: matched, fresh, postRestart, absent })
  }
  const completeEpochs = [...coverage].filter(([, surfaces]) => m.policy.requiredSurfaces.every(s => surfaces.has(s))).map(([epoch]) => epoch).sort((a, b) => a - b)
  const missing = []; for (const [epoch, surfaces] of coverage) for (const surface of m.policy.requiredSurfaces) if (!surfaces.has(surface)) missing.push({ epoch, surface })
  const thresholdMet = completeEpochs.length >= m.policy.minPostRestartEpochs
  const verdict = identityMatched && requestBound && approvalBound && chronologyValid && thresholdMet && !resurrectionDetected ? 'verified-absent' : 'rejected'
  return { schemaVersion: 1, verdict, proofId: m.proofId, subjectHash: m.subjectHash, deletionIdHash: sha(request.deletionId || ''), checks: { identityMatched, requestBound, approvalBound, chronologyValid, thresholdMet, resurrectionDetected }, policy: { requiredSurfaces: [...m.policy.requiredSurfaces].sort(), minPostRestartEpochs: m.policy.minPostRestartEpochs, completeEpochs }, observations: rows, disclosures: { missing, staleObservationIds: rows.filter(r => !r.fresh).map(r => r.id), invalidObservationIds: rows.filter(r => !r.digestMatched || !r.identityMatched || !r.postRestart).map(r => r.id) }, destructiveActions: false, returnsReceiptBodies: false }
}

export async function verifyRetentionSettlement({ workspaceRoot, manifestPath, artifactDir }) {
  const root = resolve(workspaceRoot); const manifestBytes = await safeFile(root, manifestPath); const m = parseManifest(manifestBytes.toString('utf8')); const request = await safeFile(root, m.request.path, m.request.sha256); const tombstone = await safeFile(root, m.tombstone.path, m.tombstone.sha256); const observations = await Promise.all(m.observations.map(x => safeFile(root, x.path, x.sha256)))
  const report = evaluateRetentionSettlement({ manifestJson: manifestBytes.toString('utf8'), requestJson: request.toString('utf8'), tombstoneJson: tombstone.toString('utf8'), observationsJson: observations.map(x => x.toString('utf8')) })
  const bytes = Buffer.from(`${stable(report)}\n`); const digest = sha(bytes); const dir = await safeArtifactDir(root, artifactDir); const out = resolve(dir, `retention-settlement-${digest}.json`)
  try { await writeFile(out, bytes, { flag: 'wx' }) } catch (error) { if (error.code !== 'EEXIST') throw error; const old = await readFile(out); if (!old.equals(bytes)) throw fail('ARTIFACT_DIVERGED', 'content-addressed artifact diverged') }
  const readBack = await readFile(out); if (sha(readBack) !== digest) throw fail('READBACK_FAILED', 'artifact read-back verification failed')
  return { ...report, artifact: { path: relative(root, out).replaceAll('\\', '/'), sha256: digest, verifiedByReadBack: true } }
}
