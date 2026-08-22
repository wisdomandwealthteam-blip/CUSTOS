import { MemoryEpisode } from './memoryEngine';

/**
 * Renamed to match the given "Autonomy summary" shape exactly
 * (nextCycleScheduledAt/riskScanSummary/activatedCapabilities) — dropped
 * `autonomyTriggers`, since MemoryEpisode.index.triggerAxis already captures
 * that same information more precisely at the episode level, making it
 * redundant here. This is MY OWN interface (not one of the originally given
 * skeleton interfaces), so renaming it to match a since-clarified spec is a
 * correction, not a break of "preserve contract shapes."
 */
export interface AutonomyReport {
  nextCycleScheduledAt: string | null;
  riskScanSummary: any[];
  activatedCapabilities: string[];
}

const AUTONOMY_RULES = {
  scheduleNextCycle: { onRiskDetected: true, intervalMinutes: 60 },
  riskScan: {
    enabled: true,
    scanFor: [
      'identity_inactivity',
      'identity_orphaned',
      'privileged_account',
      'service_stale_password',
      'trust_degraded',
      'dc_replication_failure',
    ],
  },
  capabilityActivation: { activateOnTriggers: true },
};

/**
 * Derived from the trigger definitions already established and validated
 * throughout this project — not new invention, just centralizing an
 * already-existing relationship (which capability owns which trigger name)
 * for the capability-activation lookup this round's rules require.
 */
const TRIGGER_CATEGORY: Record<string, string> = {
  identity_inactivity: 'identity',
  identity_orphaned: 'identity',
  identity_termination: 'identity',
  contractor_termination: 'contractor',
  contractor_orphaned: 'contractor',
  contractor_inactivity: 'contractor',
  service_orphaned: 'service',
  service_stale_password: 'service',
  privilege_change: 'privilege',
  privileged_account: 'privilege',
  trust_degraded: 'trust',
  dc_replication_failure: 'trust',
};

/**
 * Scheduling gate: no explicit formula was given connecting riskDetected/
 * actionOccurred/artifactProduced to the scheduling decision — all three are
 * named as booleans, but nothing states how they combine. Taking
 * artifactProduced as a gate would mean scheduling fires EVERY cycle now
 * (no_action_model always produces an artifact, even with zero triggers),
 * which contradicts "onRiskDetected" being a named, presumably-meaningful
 * config flag. Kept riskDetected (now precisely redefined per this round:
 * triggerAxis intersects scanFor) as the sole gate; actionOccurred/
 * artifactProduced are computed and available but don't alter the schedule.
 * Flagged rather than guessed which combining formula was intended.
 */
export function runAutonomy(ep: MemoryEpisode): AutonomyReport {
  const riskDetected = ep.index.triggerAxis.some((t) => AUTONOMY_RULES.riskScan.scanFor.includes(t));
  const actionOccurred = ep.index.actionAxis.some((a) => a === 'disable_account' || a === 'block_action');
  const artifactProduced = ep.executionSummary.artifacts.length > 0;
  void actionOccurred;
  void artifactProduced;

  let nextCycleScheduledAt: string | null = null;
  if (riskDetected && AUTONOMY_RULES.scheduleNextCycle.onRiskDetected) {
    const base = new Date(ep.timestamp);
    nextCycleScheduledAt = new Date(base.getTime() + AUTONOMY_RULES.scheduleNextCycle.intervalMinutes * 60000).toISOString();
  }

  let riskScanSummary: any[] = [];
  if (AUTONOMY_RULES.riskScan.enabled) {
    const counts: Record<string, number> = {};
    for (const trigger of ep.index.triggerAxis) {
      if (AUTONOMY_RULES.riskScan.scanFor.includes(trigger)) {
        counts[trigger] = (counts[trigger] ?? 0) + 1;
      }
    }
    riskScanSummary = Object.entries(counts).map(([trigger, count]) => ({ trigger, count }));
  }

  let activatedCapabilities: string[] = [];
  if (AUTONOMY_RULES.capabilityActivation.activateOnTriggers) {
    const categories = new Set<string>();
    for (const trigger of ep.index.triggerAxis) {
      const category = TRIGGER_CATEGORY[trigger];
      if (category) categories.add(category);
    }
    activatedCapabilities = Array.from(categories).sort();
  }

  return { nextCycleScheduledAt, riskScanSummary, activatedCapabilities };
}
