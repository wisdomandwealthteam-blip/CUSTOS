import { GovernanceDecision } from './governanceEngine';
import { ReasoningOutput } from './reasoningEngine';
import { AgentInput } from '../contracts/AgentInput';

/**
 * Artifact structure CORRECTED to match the given execution artifact model —
 * FLAT (targetId/reason/evidence directly on the artifact), not the nested
 * {artifactType, fields: {...}} shape from the prior round. This is a real
 * correction, not an addition.
 *
 * Action vocabulary is the given closed set: disable_account (allowed
 * action) -> disable_account_model, block_action (blocked action) ->
 * blocked_action_model, no_action (zero triggers this whole cycle) ->
 * exactly one no_action_model artifact. blocked_action_model is now one
 * artifact PER blocked action (matching disable_account_model's shape and
 * the "every action must include targetId, reason, evidence,
 * executionContext" coherence rule) — not the single summary object this
 * used to be.
 *
 * SIGNATURE CHANGE, FLAGGED: cycleId/episodeId are new required parameters.
 * executionContext.episodeId/cycleId must match the SAME values the eventual
 * memory episode uses — they're generated ONCE in cycleIdentity.ts, at the
 * start of the whole cycle (before Diagnostics), and threaded through here
 * and into writeMemoryEpisode, rather than being independently regenerated
 * at each stage (which would produce mismatched ids — exactly what "no
 * cross-engine drift" forbids). governanceDecisionId comes from
 * `gov.governanceDecisionId` directly, no separate parameter needed.
 */

export interface ExecutionArtifact {
  artifactId: string;
  artifactType: 'disable_account_model' | 'blocked_action_model' | 'no_action_model';
  timestamp: string;
  targetId: string | null;
  reason: string;
  evidence: any;
  executionContext: {
    cycleId: string;
    episodeId: string;
    governanceDecisionId: string;
  };
}

export interface ExecutionSummary {
  executedTasks: string[];
  artifacts: ExecutionArtifact[];
  executionNotes: string[];
}

function findEvidence(category: string, id: string, trigger: string, reasoning: ReasoningOutput): any {
  const arraysByCategory: Record<string, { idField: 'accountId' | 'entityId'; records: any[] }> = {
    identity: { idField: 'accountId', records: reasoning.identityTriggers },
    privilege: { idField: 'accountId', records: reasoning.privilegeTriggers },
    service: { idField: 'accountId', records: reasoning.serviceTriggers },
    contractor: { idField: 'accountId', records: reasoning.contractorTriggers },
    trust: { idField: 'entityId', records: reasoning.trustTriggers },
  };

  const bucket = arraysByCategory[category];
  if (!bucket) return null;

  const record = bucket.records.find((r) => r[bucket.idField] === id && (r.triggers ?? []).includes(trigger));
  return record?.basis ?? null;
}

function parseDescriptor(descriptor: string): { category: string; id: string; trigger: string } {
  const [category, id, trigger] = descriptor.split(':');
  return { category, id, trigger };
}

let artifactCounter = 0;
function generateArtifactId(): string {
  artifactCounter += 1;
  return `artifact-${Date.now()}-${artifactCounter}`;
}

function buildArtifact(
  artifactType: ExecutionArtifact['artifactType'],
  targetId: string | null,
  reason: string,
  evidence: any,
  timestamp: string,
  cycleId: string,
  episodeId: string,
  governanceDecisionId: string
): ExecutionArtifact {
  return {
    artifactId: generateArtifactId(),
    artifactType,
    timestamp,
    targetId,
    reason,
    evidence,
    executionContext: { cycleId, episodeId, governanceDecisionId },
  };
}

export function runExecution(
  gov: GovernanceDecision,
  reasoning: ReasoningOutput,
  environment: AgentInput['environment'],
  cycleId: string,
  episodeId: string
): ExecutionSummary {
  const executedTasks: string[] = [];
  const artifacts: ExecutionArtifact[] = [];

  for (const descriptor of gov.allowedActions) {
    const { category, id, trigger } = parseDescriptor(descriptor);
    executedTasks.push(descriptor);
    artifacts.push(
      buildArtifact(
        'disable_account_model',
        id,
        trigger,
        findEvidence(category, id, trigger, reasoning),
        environment.timestamp,
        cycleId,
        episodeId,
        gov.governanceDecisionId
      )
    );
  }

  for (const descriptor of gov.blockedActions) {
    const { category, id, trigger } = parseDescriptor(descriptor);
    artifacts.push(
      buildArtifact(
        'blocked_action_model',
        id,
        trigger,
        findEvidence(category, id, trigger, reasoning),
        environment.timestamp,
        cycleId,
        episodeId,
        gov.governanceDecisionId
      )
    );
  }

  if (gov.allowedActions.length === 0 && gov.blockedActions.length === 0) {
    artifacts.push(
      buildArtifact('no_action_model', null, 'no_action', null, environment.timestamp, cycleId, episodeId, gov.governanceDecisionId)
    );
  }

  return {
    executedTasks,
    artifacts,
    executionNotes: [
      'Modeling mode active for this cycle: no destructive operations, no real account/privilege/trust changes were made.',
    ],
  };
}
