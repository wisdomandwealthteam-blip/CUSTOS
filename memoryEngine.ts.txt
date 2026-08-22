import { ExecutionSummary, ExecutionArtifact } from './executionEngine';
import { GovernanceDecision } from './governanceEngine';
import { AgentInput } from '../contracts/AgentInput';
import { AutonomyReport } from './autonomyEngine';
import { aggregateEvidence, EvidenceEntry } from '../capabilities/evidenceAnalytics';

/**
 * REPLACES the originally given MemoryEpisode shape entirely (environment/
 * blockedActions/artifacts/memoryIndex are gone), per the explicit memory
 * indexing rules supplied — same pattern as governancePolicy/
 * executionArtifacts/autonomyRules each fully replacing their respective
 * interim designs.
 *
 * TWO-PHASE CONSTRUCTION, FLAGGED: autonomySummary/riskAxis need autonomy's
 * output, but section 8's frozen sequence runs Memory BEFORE Autonomy — a
 * real, unavoidable conflict between "this data must be in the memory
 * episode" and "memory runs before the engine that produces it." Not solved
 * by reordering the frozen sequence (forbidden) or hidden state (forbidden).
 * Solved instead by splitting into two functions:
 *   - writeMemoryEpisode(): runs in memory's normal frozen-sequence slot,
 *     computes everything derivable from execution+governance alone.
 *   - finalizeMemoryEpisode(): runs AFTER autonomy, fills in riskAxis and
 *     autonomySummary. Not one of the six named engines being reordered —
 *     an assembly step added after the fixed sequence completes.
 */

export interface MemoryEpisodeIndex {
  identityAxis: string[];
  triggerAxis: string[];
  actionAxis: string[];
  artifactAxis: string[];
  riskAxis: string[];
}

export interface MemoryEpisode {
  episodeId: string;
  cycleId: string;
  timestamp: string;
  index: MemoryEpisodeIndex;
  executionSummary: {
    actionsAllowed: string[];
    actionsBlocked: string[];
    artifacts: ExecutionArtifact[];
  };
  autonomySummary: {
    nextCycleScheduledAt: string | null;
    riskScanSummary: any[];
    activatedCapabilities: string[];
  };
  evidence: EvidenceEntry[];
}

const ACTION_TYPE_BY_ARTIFACT_TYPE: Record<string, string> = {
  disable_account_model: 'disable_account',
  blocked_action_model: 'block_action',
  no_action_model: 'no_action',
};

function dedupe(values: (string | null)[]): string[] {
  return Array.from(new Set(values.filter((v): v is string => v !== null)));
}

export function writeMemoryEpisode(
  execution: ExecutionSummary,
  environment: AgentInput['environment'],
  governance: GovernanceDecision,
  cycleId: string,
  episodeId: string
): MemoryEpisode {
  const identityAxis = dedupe(execution.artifacts.map((a) => a.targetId));

  const triggerAxis = dedupe(
    execution.artifacts.filter((a) => a.artifactType !== 'no_action_model').map((a) => a.reason)
  );

  const actionAxis = dedupe(execution.artifacts.map((a) => ACTION_TYPE_BY_ARTIFACT_TYPE[a.artifactType] ?? null));

  const artifactAxis = dedupe(execution.artifacts.map((a) => a.artifactType));

  return {
    episodeId,
    cycleId,
    timestamp: environment.timestamp,
    index: {
      identityAxis,
      triggerAxis,
      actionAxis,
      artifactAxis,
      riskAxis: [],
    },
    executionSummary: {
      actionsAllowed: governance.allowedActions,
      actionsBlocked: governance.blockedActions,
      artifacts: execution.artifacts,
    },
    autonomySummary: {
      nextCycleScheduledAt: null,
      riskScanSummary: [],
      activatedCapabilities: [],
    },
    evidence: aggregateEvidence(execution.artifacts),
  };
}

export function finalizeMemoryEpisode(episode: MemoryEpisode, autonomy: AutonomyReport): MemoryEpisode {
  return {
    ...episode,
    index: {
      ...episode.index,
      riskAxis: autonomy.riskScanSummary.map((r: any) => r.trigger),
    },
    autonomySummary: {
      nextCycleScheduledAt: autonomy.nextCycleScheduledAt,
      riskScanSummary: autonomy.riskScanSummary,
      activatedCapabilities: autonomy.activatedCapabilities,
    },
  };
}
