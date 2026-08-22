/**
 * capabilities/trustDcGovernance.ts
 *
 * REPLACES the earlier version's trust_decommission/dc_decommission checks.
 * Those were explicitly flagged last round as unverified guesses at plausible
 * field values, never confirmed by any reference. Neither trigger name
 * appears anywhere in governancePolicy or autonomyRules.riskScan.scanFor —
 * the real trust trigger vocabulary is trust_degraded/dc_replication_failure,
 * driven by explicitly-supplied threshold lists
 * (agentConfig.rules.trustRules.degradedLevels/replicationFailureStates).
 * This is a correction, not an addition — the old checks are gone.
 *
 * trust_degraded: trustHealthStatus is a member of rules.degradedLevels.
 * dc_replication_failure: replicationStatus is a member of
 * rules.replicationFailureStates.
 */

export interface TrustTrigger {
  entityId: string;
  triggers: string[];
  basis: {
    trustType: any;
    trustDirection: any;
    protocol: any[];
    dcRole: any;
    replicationStatus: any;
    trustHealthStatus: any;
  };
}

interface TrustRules {
  degradedLevels?: string[];
  replicationFailureStates?: string[];
}

function recordId(obj: any): string | null {
  return obj?.entityId ?? obj?.id ?? null;
}

/** Pure function. */
export function runTrustDcGovernance(trustMap: any, rules: TrustRules | undefined): TrustTrigger[] {
  const entities = trustMap?.entities ?? [];
  const results: TrustTrigger[] = [];

  for (const ent of entities) {
    const id = recordId(ent);
    if (!id) continue;

    const triggers: string[] = [];

    if (rules?.degradedLevels && rules.degradedLevels.includes(ent.trustHealthStatus)) {
      triggers.push('trust_degraded');
    }
    if (rules?.replicationFailureStates && rules.replicationFailureStates.includes(ent.replicationStatus)) {
      triggers.push('dc_replication_failure');
    }

    if (triggers.length === 0) continue;

    results.push({
      entityId: id,
      triggers,
      basis: {
        trustType: ent.trustType ?? null,
        trustDirection: ent.trustDirection ?? null,
        protocol: ent.protocol ?? [],
        dcRole: ent.dcRole ?? null,
        replicationStatus: ent.replicationStatus ?? null,
        trustHealthStatus: ent.trustHealthStatus ?? null,
      },
    });
  }

  return results;
}
