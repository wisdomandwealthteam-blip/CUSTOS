/**
 * capabilities/serviceAccountGovernance.ts
 *
 * An account is a service account if identityMap[id].type==="service" OR
 * identityMap[id].category==="system".
 *
 * service_orphaned: reuses orphanedMap.orphanedStatus (same signal
 * identityGovernance/contractorGovernance use), GATED on
 * agentConfig.rules.serviceAccountRules.orphanedIfNoOwner===true.
 *
 * service_stale_password: NOW IMPLEMENTED. Fires when
 * (currentTimestamp - uacMap[accountId].passwordLastChanged) in days >=
 * serviceAccountRules.stalePasswordDays. "currentTimestamp" isn't sourced
 * anywhere in the given definition — using environment.timestamp for it,
 * consistent with every other place in this pipeline that needed a "now"
 * (the execution artifact timestamp, autonomy's scheduledNextCycle), to
 * keep the whole system deterministic rather than a fresh Date.now() call.
 * If passwordLastChanged is missing, unparseable, or stalePasswordDays isn't
 * configured, the trigger simply doesn't fire — no crash, no false positive.
 *
 * NOTE: this capability's `basis` object is uniformly shaped across BOTH its
 * triggers (service_orphaned and service_stale_password together), same
 * pattern as every other capability in this pipeline — not re-shaped per
 * individual trigger. The evidence definition given for service_stale_password
 * was exactly {passwordLastChanged, stalePasswordDays}; this basis object is
 * a superset of that (also carries orphanedStatus, null when irrelevant) —
 * flagged explicitly rather than silently delivered as an exact match.
 */

export interface ServiceAccountTrigger {
  accountId: string;
  triggers: string[];
  basis: {
    orphanedStatus: any;
    passwordLastChanged?: string;
    stalePasswordDays?: number;
  };
}

interface ServiceAccountRules {
  stalePasswordDays?: number;
  orphanedIfNoOwner?: boolean;
}

function recordId(obj: any): string | null {
  return obj?.accountId ?? obj?.id ?? null;
}

function indexById(records: any[]): Map<string, any> {
  const map = new Map<string, any>();
  for (const r of records ?? []) {
    const id = recordId(r);
    if (id) map.set(id, r);
  }
  return map;
}

function isServiceAccount(identityMap: any, id: string): boolean {
  const identity = identityMap?.[id];
  return identity?.type === 'service' || identity?.category === 'system';
}

function daysBetween(laterISO: string, earlierISO: string): number | null {
  const later = new Date(laterISO).getTime();
  const earlier = new Date(earlierISO).getTime();
  if (Number.isNaN(later) || Number.isNaN(earlier)) return null;
  return (later - earlier) / (1000 * 60 * 60 * 24);
}

/** Pure function. */
export function runServiceAccountGovernance(
  identityMap: any,
  orphanedMap: any,
  uacMap: any,
  rules: ServiceAccountRules | undefined,
  currentTimestamp: string
): ServiceAccountTrigger[] {
  const orphanedAccts = indexById(orphanedMap?.accounts ?? []);
  const uacAccts = indexById(uacMap?.accounts ?? []);
  const results: ServiceAccountTrigger[] = [];

  const candidateIds = identityMap ? Object.keys(identityMap) : [];

  for (const id of candidateIds) {
    if (!isServiceAccount(identityMap, id)) continue;

    const orphan = orphanedAccts.get(id) ?? null;
    const uac = uacAccts.get(id) ?? null;
    const triggers: string[] = [];

    if (
      orphan &&
      (orphan.orphanedStatus === 'orphaned' || orphan.orphanedStatus === 'orphaned_critical') &&
      rules?.orphanedIfNoOwner === true
    ) {
      triggers.push('service_orphaned');
    }

    if (uac?.passwordLastChanged && rules?.stalePasswordDays !== undefined) {
      const age = daysBetween(currentTimestamp, uac.passwordLastChanged);
      if (age !== null && age >= rules.stalePasswordDays) {
        triggers.push('service_stale_password');
      }
    }

    if (triggers.length === 0) continue;

    const basis: ServiceAccountTrigger['basis'] = {
      orphanedStatus: orphan?.orphanedStatus ?? null,
    };
    if (triggers.includes('service_stale_password')) {
      basis.passwordLastChanged = uac.passwordLastChanged;
      basis.stalePasswordDays = rules!.stalePasswordDays;
    }

    results.push({ accountId: id, triggers, basis });
  }

  return results;
}
