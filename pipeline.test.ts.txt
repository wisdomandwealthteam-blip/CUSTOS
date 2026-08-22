import assert from 'assert';
import { runIdentityGovernance } from '../capabilities/identityGovernance';
import { runPrivilegeGovernance } from '../capabilities/privilegeGovernance';
import { runTrustDcGovernance } from '../capabilities/trustDcGovernance';
import { runServiceAccountGovernance } from '../capabilities/serviceAccountGovernance';
import { runContractorGovernance } from '../capabilities/contractorGovernance';
import { runEvidenceAnalytics, aggregateEvidence } from '../capabilities/evidenceAnalytics';
import { runReasoning } from '../engines/reasoningEngine';
import { runGovernance } from '../engines/governanceEngine';
import { runExecution } from '../engines/executionEngine';
import { writeMemoryEpisode, finalizeMemoryEpisode } from '../engines/memoryEngine';
import { runAutonomy } from '../engines/autonomyEngine';
import { runDiagnostics } from '../engines/diagnosticsEngine';
import { generateCycleIdentity } from '../engines/cycleIdentity';
import { AgentInput } from '../contracts/AgentInput';

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`ok - ${name}`);
    passed++;
  } catch (err) {
    console.error(`FAIL - ${name}`);
    console.error(err);
    failed++;
  }
}

const FIXED_ENV = { tenantId: 't', timestamp: '2026-01-01T00:00:00.000Z', region: 'us-east-1' };

test('identityGovernance: employee-category account gets real trigger names', () => {
  const identityMap = { jdoe: { category: 'employee', type: 'user' } };
  const result = runIdentityGovernance(
    { accounts: [{ accountId: 'jdoe', orphanedStatus: 'orphaned_critical', hrStatus: 'terminated' }] },
    { accounts: [{ accountId: 'jdoe', inactivityDays: 45, inactivityStatus: 'inactive_>=30' }] },
    identityMap
  );
  assert.strictEqual(result.length, 1);
  assert.deepStrictEqual(result[0].triggers.sort(), ['identity_inactivity', 'identity_orphaned', 'identity_termination'].sort());
});

test('privilegeGovernance: privilegedAccountFlag=true triggers privileged_account', () => {
  const result = runPrivilegeGovernance({ accounts: [{ accountId: 'a1', privilegedAccountFlag: true }] });
  assert.ok(result[0].triggers.includes('privileged_account'));
});

test('trustDcGovernance: trust_degraded / dc_replication_failure from real trustRules', () => {
  const result = runTrustDcGovernance(
    { entities: [{ entityId: 't1', trustHealthStatus: 'degraded', replicationStatus: 'failed' }] },
    { degradedLevels: ['degraded', 'critical'], replicationFailureStates: ['failed'] }
  );
  assert.deepStrictEqual(result[0].triggers.sort(), ['dc_replication_failure', 'trust_degraded'].sort());
});

test('governanceEngine: produces a governanceDecisionId', () => {
  const reasoning = { identityTriggers: [], privilegeTriggers: [], serviceTriggers: [], contractorTriggers: [], trustTriggers: [], riskLevels: [] };
  const gov = runGovernance(reasoning as any);
  assert.ok(typeof gov.governanceDecisionId === 'string' && gov.governanceDecisionId.length > 0);
});

test('governanceEngine: allow vs block split unchanged', () => {
  const reasoning = {
    identityTriggers: [], privilegeTriggers: [], serviceTriggers: [], contractorTriggers: [], trustTriggers: [],
    riskLevels: [{ id: 'a1', category: 'identity', triggers: ['identity_inactivity'] }, { id: 'a2', category: 'privilege', triggers: ['privilege_change'] }],
  };
  const gov = runGovernance(reasoning as any);
  assert.deepStrictEqual(gov.allowedActions, ['identity:a1:identity_inactivity']);
  assert.deepStrictEqual(gov.blockedActions, ['privilege:a2:privilege_change']);
});

function fakeGov(allowed: string[], blocked: string[]) {
  return { governanceDecisionId: 'gov-1', allowedActions: allowed, blockedActions: blocked, governanceNotes: [] };
}

const emptyReasoning = { identityTriggers: [], privilegeTriggers: [], serviceTriggers: [], contractorTriggers: [], trustTriggers: [] };

test('executionEngine: allowed action produces a FLAT disable_account_model artifact', () => {
  const reasoning = {
    ...emptyReasoning,
    identityTriggers: [{ accountId: 'a1', triggers: ['identity_inactivity'], basis: { inactivity: { inactivityDays: 45 } } }],
  };
  const gov = fakeGov(['identity:a1:identity_inactivity'], []);
  const exec = runExecution(gov as any, reasoning as any, FIXED_ENV, 'cycle-1', 'episode-1');

  assert.strictEqual(exec.artifacts.length, 1);
  const artifact = exec.artifacts[0];
  assert.strictEqual(artifact.artifactType, 'disable_account_model');
  assert.strictEqual(artifact.targetId, 'a1');
  assert.strictEqual(artifact.reason, 'identity_inactivity');
  assert.deepStrictEqual(artifact.evidence, { inactivity: { inactivityDays: 45 } });
  assert.strictEqual(artifact.executionContext.cycleId, 'cycle-1');
  assert.strictEqual(artifact.executionContext.episodeId, 'episode-1');
  assert.strictEqual(artifact.executionContext.governanceDecisionId, 'gov-1');
  assert.ok(typeof artifact.artifactId === 'string' && artifact.artifactId.length > 0);
});

test('executionEngine: blocked action produces its OWN blocked_action_model artifact (not a summary)', () => {
  const reasoning = {
    ...emptyReasoning,
    privilegeTriggers: [{ accountId: 'a1', triggers: ['privilege_change'], basis: { privilegeLevel: 'standard' } }],
  };
  const gov = fakeGov([], ['privilege:a1:privilege_change']);
  const exec = runExecution(gov as any, reasoning as any, FIXED_ENV, 'cycle-1', 'episode-1');

  assert.strictEqual(exec.artifacts.length, 1);
  assert.strictEqual(exec.artifacts[0].artifactType, 'blocked_action_model');
  assert.strictEqual(exec.artifacts[0].targetId, 'a1');
  assert.strictEqual(exec.artifacts[0].reason, 'privilege_change');
});

test('executionEngine: multiple blocked actions produce multiple artifacts, one each', () => {
  const reasoning = {
    ...emptyReasoning,
    privilegeTriggers: [
      { accountId: 'a1', triggers: ['privilege_change'], basis: {} },
      { accountId: 'a2', triggers: ['privilege_change'], basis: {} },
    ],
  };
  const gov = fakeGov([], ['privilege:a1:privilege_change', 'privilege:a2:privilege_change']);
  const exec = runExecution(gov as any, reasoning as any, FIXED_ENV, 'cycle-1', 'episode-1');
  assert.strictEqual(exec.artifacts.length, 2);
  assert.deepStrictEqual(exec.artifacts.map((a) => a.targetId).sort(), ['a1', 'a2']);
});

test('executionEngine: zero triggers -> exactly one no_action_model artifact', () => {
  const gov = fakeGov([], []);
  const exec = runExecution(gov as any, emptyReasoning as any, FIXED_ENV, 'cycle-1', 'episode-1');
  assert.strictEqual(exec.artifacts.length, 1);
  assert.strictEqual(exec.artifacts[0].artifactType, 'no_action_model');
  assert.strictEqual(exec.artifacts[0].targetId, null);
  assert.strictEqual(exec.artifacts[0].evidence, null);
});

test('executionEngine: artifactIds are unique even for same-millisecond artifacts', () => {
  const reasoning = {
    ...emptyReasoning,
    privilegeTriggers: [
      { accountId: 'a1', triggers: ['privilege_change'], basis: {} },
      { accountId: 'a2', triggers: ['privilege_change'], basis: {} },
      { accountId: 'a3', triggers: ['privilege_change'], basis: {} },
    ],
  };
  const gov = fakeGov([], ['privilege:a1:privilege_change', 'privilege:a2:privilege_change', 'privilege:a3:privilege_change']);
  const exec = runExecution(gov as any, reasoning as any, FIXED_ENV, 'cycle-1', 'episode-1');
  const ids = exec.artifacts.map((a) => a.artifactId);
  assert.strictEqual(new Set(ids).size, ids.length);
});

test('aggregateEvidence: extracts targetId/reason/evidence directly from flat artifacts', () => {
  const artifacts = [
    { artifactId: 'x', artifactType: 'disable_account_model', timestamp: 't', targetId: 'a1', reason: 'identity_inactivity', evidence: { foo: 1 }, executionContext: {} as any },
  ];
  const result = aggregateEvidence(artifacts as any);
  assert.deepStrictEqual(result, [{ targetId: 'a1', reason: 'identity_inactivity', evidence: { foo: 1 } }]);
});

function buildExecutionSummary(artifacts: any[]) {
  return { executedTasks: [], artifacts, executionNotes: [] };
}

test('memoryEngine: identityAxis excludes null targetId (no_action_model)', () => {
  const artifacts = [
    { artifactId: 'x1', artifactType: 'disable_account_model', timestamp: 't', targetId: 'a1', reason: 'identity_inactivity', evidence: null, executionContext: {} as any },
    { artifactId: 'x2', artifactType: 'no_action_model', timestamp: 't', targetId: null, reason: 'no_action', evidence: null, executionContext: {} as any },
  ];
  const gov = fakeGov(['identity:a1:identity_inactivity'], []);
  const episode = writeMemoryEpisode(buildExecutionSummary(artifacts) as any, FIXED_ENV, gov as any, 'cycle-1', 'episode-1');
  assert.deepStrictEqual(episode.index.identityAxis, ['a1']);
});

test('memoryEngine: triggerAxis excludes the no_action placeholder reason', () => {
  const artifacts = [
    { artifactId: 'x1', artifactType: 'no_action_model', timestamp: 't', targetId: null, reason: 'no_action', evidence: null, executionContext: {} as any },
  ];
  const gov = fakeGov([], []);
  const episode = writeMemoryEpisode(buildExecutionSummary(artifacts) as any, FIXED_ENV, gov as any, 'cycle-1', 'episode-1');
  assert.deepStrictEqual(episode.index.triggerAxis, []);
});

test('memoryEngine: actionAxis maps artifactType to the action vocabulary', () => {
  const artifacts = [
    { artifactId: 'x1', artifactType: 'disable_account_model', timestamp: 't', targetId: 'a1', reason: 'identity_inactivity', evidence: null, executionContext: {} as any },
    { artifactId: 'x2', artifactType: 'blocked_action_model', timestamp: 't', targetId: 'a2', reason: 'privilege_change', evidence: null, executionContext: {} as any },
  ];
  const gov = fakeGov(['identity:a1:identity_inactivity'], ['privilege:a2:privilege_change']);
  const episode = writeMemoryEpisode(buildExecutionSummary(artifacts) as any, FIXED_ENV, gov as any, 'cycle-1', 'episode-1');
  assert.deepStrictEqual(episode.index.actionAxis.sort(), ['block_action', 'disable_account'].sort());
});

test('memoryEngine: no_action_model alone yields actionAxis=["no_action"]', () => {
  const artifacts = [
    { artifactId: 'x1', artifactType: 'no_action_model', timestamp: 't', targetId: null, reason: 'no_action', evidence: null, executionContext: {} as any },
  ];
  const gov = fakeGov([], []);
  const episode = writeMemoryEpisode(buildExecutionSummary(artifacts) as any, FIXED_ENV, gov as any, 'cycle-1', 'episode-1');
  assert.deepStrictEqual(episode.index.actionAxis, ['no_action']);
});

test('memoryEngine: artifactAxis lists distinct artifactTypes', () => {
  const artifacts = [
    { artifactId: 'x1', artifactType: 'disable_account_model', timestamp: 't', targetId: 'a1', reason: 'r', evidence: null, executionContext: {} as any },
    { artifactId: 'x2', artifactType: 'disable_account_model', timestamp: 't', targetId: 'a2', reason: 'r', evidence: null, executionContext: {} as any },
  ];
  const gov = fakeGov(['a:a1:r', 'a:a2:r'], []);
  const episode = writeMemoryEpisode(buildExecutionSummary(artifacts) as any, FIXED_ENV, gov as any, 'cycle-1', 'episode-1');
  assert.deepStrictEqual(episode.index.artifactAxis, ['disable_account_model']);
});

test('memoryEngine: riskAxis is empty before finalize, populated after', () => {
  const artifacts = [
    { artifactId: 'x1', artifactType: 'disable_account_model', timestamp: 't', targetId: 'a1', reason: 'identity_inactivity', evidence: null, executionContext: {} as any },
  ];
  const gov = fakeGov(['identity:a1:identity_inactivity'], []);
  const preliminary = writeMemoryEpisode(buildExecutionSummary(artifacts) as any, FIXED_ENV, gov as any, 'cycle-1', 'episode-1');
  assert.deepStrictEqual(preliminary.index.riskAxis, []);
  assert.strictEqual(preliminary.autonomySummary.nextCycleScheduledAt, null);

  const autonomy = runAutonomy(preliminary);
  const final = finalizeMemoryEpisode(preliminary, autonomy);
  assert.deepStrictEqual(final.index.riskAxis, ['identity_inactivity']);
});

test('memoryEngine: cycleId/episodeId passed in are reused verbatim, not regenerated', () => {
  const gov = fakeGov([], []);
  const episode = writeMemoryEpisode(buildExecutionSummary([]) as any, FIXED_ENV, gov as any, 'my-cycle-id', 'my-episode-id');
  assert.strictEqual(episode.cycleId, 'my-cycle-id');
  assert.strictEqual(episode.episodeId, 'my-episode-id');
});

test('autonomyEngine: riskDetected requires triggerAxis intersecting scanFor specifically', () => {
  const episode = {
    episodeId: 'e1', cycleId: 'c1', timestamp: '2026-01-01T00:00:00.000Z',
    index: { identityAxis: ['a1'], triggerAxis: ['identity_termination'], actionAxis: ['disable_account'], artifactAxis: ['disable_account_model'], riskAxis: [] },
    executionSummary: { actionsAllowed: ['identity:a1:identity_termination'], actionsBlocked: [], artifacts: [{}] },
    autonomySummary: { nextCycleScheduledAt: null, riskScanSummary: [], activatedCapabilities: [] },
    evidence: [],
  };
  const report = runAutonomy(episode as any);
  assert.strictEqual(report.nextCycleScheduledAt, null);
});

test('autonomyEngine: riskDetected true when triggerAxis has a scanFor member -> schedules', () => {
  const episode = {
    episodeId: 'e1', cycleId: 'c1', timestamp: '2026-01-01T00:00:00.000Z',
    index: { identityAxis: ['a1'], triggerAxis: ['identity_inactivity'], actionAxis: ['disable_account'], artifactAxis: ['disable_account_model'], riskAxis: [] },
    executionSummary: { actionsAllowed: ['identity:a1:identity_inactivity'], actionsBlocked: [], artifacts: [{}] },
    autonomySummary: { nextCycleScheduledAt: null, riskScanSummary: [], activatedCapabilities: [] },
    evidence: [],
  };
  const report = runAutonomy(episode as any);
  assert.strictEqual(report.nextCycleScheduledAt, '2026-01-01T01:00:00.000Z');
});

test('autonomyEngine: no_action cycle (artifactProduced=true but riskDetected=false) does NOT schedule', () => {
  const episode = {
    episodeId: 'e1', cycleId: 'c1', timestamp: '2026-01-01T00:00:00.000Z',
    index: { identityAxis: [], triggerAxis: [], actionAxis: ['no_action'], artifactAxis: ['no_action_model'], riskAxis: [] },
    executionSummary: { actionsAllowed: [], actionsBlocked: [], artifacts: [{ artifactType: 'no_action_model' }] },
    autonomySummary: { nextCycleScheduledAt: null, riskScanSummary: [], activatedCapabilities: [] },
    evidence: [],
  };
  const report = runAutonomy(episode as any);
  assert.strictEqual(report.nextCycleScheduledAt, null);
});

test('autonomyEngine: activatedCapabilities derived from triggerAxis via the category lookup', () => {
  const episode = {
    episodeId: 'e1', cycleId: 'c1', timestamp: '2026-01-01T00:00:00.000Z',
    index: { identityAxis: ['a1', 't1'], triggerAxis: ['identity_inactivity', 'trust_degraded'], actionAxis: ['disable_account', 'block_action'], artifactAxis: ['disable_account_model', 'blocked_action_model'], riskAxis: [] },
    executionSummary: { actionsAllowed: [], actionsBlocked: [], artifacts: [{}, {}] },
    autonomySummary: { nextCycleScheduledAt: null, riskScanSummary: [], activatedCapabilities: [] },
    evidence: [],
  };
  const report = runAutonomy(episode as any);
  assert.deepStrictEqual(report.activatedCapabilities, ['identity', 'trust']);
});

test('cycleIdentity: generates distinct cycleId and episodeId strings', () => {
  const { cycleId, episodeId } = generateCycleIdentity();
  assert.ok(cycleId.startsWith('cycle-'));
  assert.ok(episodeId.startsWith('episode-'));
  assert.notStrictEqual(cycleId, episodeId);
});

function samplePayload(): AgentInput {
  return {
    diagnostics: {
      identityMap: {
        jdoe: { id: 'jdoe', type: 'user', status: 'enabled', category: 'employee', source: 'AD', lastLogin: null },
      },
      privilegeMap: { accounts: [{ accountId: 'asmith', privilegeChanged: true }] },
      uacMap: {},
      orphanedMap: { accounts: [{ accountId: 'jdoe', orphanedStatus: 'orphaned_critical', hrStatus: 'terminated' }] },
      inactivityMap: { accounts: [{ accountId: 'jdoe', inactivityDays: 45, inactivityStatus: 'inactive_>=30' }] },
      hrMap: {},
      trustMap: {},
    },
    agentConfig: { cycleMode: 'manual', memoryMode: 'full', rules: {} },
    environment: FIXED_ENV,
  };
}

test('full pipeline: cycleId/episodeId match between execution artifacts and the final memory episode', () => {
  const { cycleId, episodeId } = generateCycleIdentity();
  const payload = samplePayload();
  const diag = runDiagnostics(payload);
  const reasoning = runReasoning(diag, payload.agentConfig.rules);
  const governance = runGovernance(reasoning);
  const execution = runExecution(governance, reasoning, payload.environment, cycleId, episodeId);
  const preliminary = writeMemoryEpisode(execution, payload.environment, governance, cycleId, episodeId);
  const autonomy = runAutonomy(preliminary);
  const episode = finalizeMemoryEpisode(preliminary, autonomy);

  assert.strictEqual(episode.cycleId, cycleId);
  assert.strictEqual(episode.episodeId, episodeId);
  for (const artifact of execution.artifacts) {
    assert.strictEqual(artifact.executionContext.cycleId, cycleId);
    assert.strictEqual(artifact.executionContext.episodeId, episodeId);
  }
});

test('full pipeline: deterministic modulo ids/timestamps', () => {
  const payload = samplePayload();
  const diag1 = runDiagnostics(payload);
  const r1 = runReasoning(diag1, payload.agentConfig.rules);
  const g1 = runGovernance(r1);

  const diag2 = runDiagnostics(payload);
  const r2 = runReasoning(diag2, payload.agentConfig.rules);
  const g2 = runGovernance(r2);

  assert.deepStrictEqual(r1, r2);
  assert.deepStrictEqual(g1.allowedActions, g2.allowedActions);
  assert.deepStrictEqual(g1.blockedActions, g2.blockedActions);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
