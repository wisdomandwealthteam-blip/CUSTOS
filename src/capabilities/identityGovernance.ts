/**
 * capabilities/identityGovernance.ts
 *
 * Handles accounts NOT routed to contractorGovernance or
 * serviceAccountGovernance. Routing rule: an account belongs here if
 * identityMap[id] is absent (no category info available — falls back here
 * rather than being silently dropped) OR identityMap[id].category==="employee"
 * AND identityMap[id].type!=="service". Accounts with category==="contractor"
 * go to contractorGovernance; category==="system" or type==="service" go to
 * serviceAccountGovernance.
 *
 * Trigger logic (inactivity/orphaned/termination) is unchanged from the
 * version validated against reference output — only the account-selection
 * scope changed, and trigger names now use the real vocabulary
 * (identity_inactivity/identity_orphaned/identity_termination) confirmed by
 * governancePolicy/autonomyRules rather than the earlier generic names.
 */

export interface IdentityTrigger {
  accountId: string;
  triggers: string[];
  basis: {
    inactivity: { inactivityDays: any; inactivityStatus: any } | null;
    orphaned: { orphanedStatus: any; hrStatus: any; managerPresence: any; employeeIdMatch: any; employeeType: any } | null;
  };
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

function belongsHere(identityMap: any, id: string): boolean {
  const identity = identityMap?.[id];
  if (!identity) return true; // no category info -> default here, not dropped
  if (identity.category === 'contractor') return false;
  if (identity.category === 'system' || identity.type === 'service') return false;
  return true;
}

/** Pure function. */
export function runIdentityGovernance(orphanedMap: any, inactivityMap: any, identityMap: any): IdentityTrigger[] {
  const orphanedAccts = indexById(orphanedMap?.accounts ?? []);
  const inactivityAccts = indexById(inactivityMap?.accounts ?? []);

  const allIds: string[] = [];
  for (const id of inactivityAccts.keys()) if (!allIds.includes(id)) allIds.push(id);
  for (const id of orphanedAccts.keys()) if (!allIds.includes(id)) allIds.push(id);

  const results: IdentityTrigger[] = [];

  for (const id of allIds) {
    if (!belongsHere(identityMap, id)) continue;

    const inact = inactivityAccts.get(id) ?? null;
    const orphan = orphanedAccts.get(id) ?? null;
    const triggers: string[] = [];

    if (inact !== null) {
      const status = inact.inactivityStatus;
      if (status !== null && status !== undefined && status !== 'active') {
        triggers.push('identity_inactivity');
      }
    }

    if (orphan !== null) {
      const status = orphan.orphanedStatus;
      if (status === 'orphaned' || status === 'orphaned_critical') {
        triggers.push('identity_orphaned');
      }
      if (orphan.hrStatus === 'terminated') {
        triggers.push('identity_termination');
      }
    }

    if (triggers.length === 0) continue;

    results.push({
      accountId: id,
      triggers,
      basis: {
        inactivity: inact !== null ? { inactivityDays: inact.inactivityDays ?? null, inactivityStatus: inact.inactivityStatus ?? null } : null,
        orphaned: orphan !== null
          ? {
              orphanedStatus: orphan.orphanedStatus ?? null,
              hrStatus: orphan.hrStatus ?? null,
              managerPresence: orphan.managerPresence ?? null,
              employeeIdMatch: orphan.employeeIdMatch ?? null,
              employeeType: orphan.employeeType ?? null,
            }
          : null,
      },
    });
  }

  return results;
}
