import { ReasoningOutput } from './reasoningEngine';

export interface GovernanceDecision {
  governanceDecisionId: string;
  allowedActions: string[];
  blockedActions: string[];
  governanceNotes: string[];
}

/**
 * governanceDecisionId: a NEW concept, introduced by the execution artifact
 * model's executionContext requirement, with no prior definition given for
 * how it's generated. Generated the same way episodeId/cycleId already are
 * (Date.now()-based) — covered by section 12's "no randomness except for
 * IDs" exception, not an invented mechanism, just the same one reused.
 *
 * GOVERNANCE_POLICY unchanged from the real policy supplied earlier.
 * Algorithm unchanged: allow-list membership determines disable_account
 * (allowed) vs block_action (blocked) — the action-coherence rules'
 * "action determination" formula is exactly this same logic, just now named
 * more precisely (disable_account/block_action instead of "allowed"/
 * "blocked" as bare English words).
 */
const GOVERNANCE_POLICY = {
  allow: {
    disable_account: [
      'identity_inactivity',
      'identity_orphaned',
      'identity_termination',
      'contractor_termination',
      'contractor_orphaned',
      'service_orphaned',
      'service_stale_password',
      'privileged_account',
    ],
  },
};

export function runGovernance(reasoning: ReasoningOutput): GovernanceDecision {
  const allowedActions: string[] = [];
  const blockedActions: string[] = [];

  for (const entry of reasoning.riskLevels) {
    for (const trigger of entry.triggers ?? []) {
      const descriptor = `${entry.category}:${entry.id}:${trigger}`;
      if (GOVERNANCE_POLICY.allow.disable_account.includes(trigger)) {
        allowedActions.push(descriptor);
      } else {
        blockedActions.push(descriptor);
      }
    }
  }

  return {
    governanceDecisionId: `governance-${Date.now()}`,
    allowedActions,
    blockedActions,
    governanceNotes: [
      'Governance policy applied: disable_account actions allowed only for triggers explicitly ' +
        'listed in governancePolicy.allow.disable_account. All other trigger-implied actions ' +
        '(block_action) are blocked.',
    ],
  };
}
