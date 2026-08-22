/**
 * capabilities/contractorGovernance.ts
 *
 * An account is a contractor if EITHER identityMap[id].category==="contractor"
 * OR hrMap[id].employmentType==="contractor" — either explicit source counts;
 * neither is required to be authoritative over the other since both denote
 * the same fact and this system tolerates partial/incomplete map data.
 *
 * contractor_termination: hrMap[id].status==="terminated", GATED on
 * agentConfig.rules.contractorRules.autoDisableOnTermination===true. If that
 * flag is false, termination is not surfaced as a trigger at all — read as
 * "don't treat contractor termination as an auto-disable-worthy signal for
 * this tenant," applied at the point the trigger would be produced.
 *
 * contractor_orphaned: reuses orphanedMap (same signal identityGovernance
 * uses), scoped to contractor accounts. No config flag gates this one —
 * contractorRules has no orphan-related flag, unlike serviceAccountRules.
 *
 * contractor_inactivity: NOT in governancePolicy.allow.disable_account, so it
 * will always end up blocked by governanceEngine — but it's still worth
 * detecting/reporting for visibility. Uses a RAW inactivityDays vs.
 * contractorRules.inactivityDays threshold comparison — different from
 * identityGovernance's pre-computed-status-based check, because this
 * threshold is contractor-specific and explicitly numeric.
 */

export interface ContractorTrigger {
  accountId: string;
  triggers: string[];
  basis: {
    hrStatus: any;
    inactivityDays: any;
    orphanedStatus: any;
  };
}

interface ContractorRules {
  inactivityDays?: number;
  autoDisableOnTermination?: boolean;
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

function isContractor(identityMap: any, hrMap: any, id: string): boolean {
  const identity = identityMap?.[id];
  const hr = hrMap?.[id];
  return identity?.category === 'contractor' || hr?.employmentType === 'contractor';
}

/** Pure function. */
export function runContractorGovernance(
  identityMap: any,
  hrMap: any,
  orphanedMap: any,
  inactivityMap: any,
  rules: ContractorRules | undefined
): ContractorTrigger[] {
  const orphanedAccts = indexById(orphanedMap?.accounts ?? []);
  const inactivityAccts = indexById(inactivityMap?.accounts ?? []);

  const candidateIds = new Set<string>();
  if (identityMap) for (const id of Object.keys(identityMap)) candidateIds.add(id);
  if (hrMap) for (const id of Object.keys(hrMap)) candidateIds.add(id);

  const results: ContractorTrigger[] = [];

  for (const id of candidateIds) {
    if (!isContractor(identityMap, hrMap, id)) continue;

    const hr = hrMap?.[id] ?? null;
    const orphan = orphanedAccts.get(id) ?? null;
    const inact = inactivityAccts.get(id) ?? null;
    const triggers: string[] = [];

    if (hr?.status === 'terminated' && rules?.autoDisableOnTermination === true) {
      triggers.push('contractor_termination');
    }

    if (orphan && (orphan.orphanedStatus === 'orphaned' || orphan.orphanedStatus === 'orphaned_critical')) {
      triggers.push('contractor_orphaned');
    }

    if (
      inact?.inactivityDays !== undefined &&
      inact?.inactivityDays !== null &&
      rules?.inactivityDays !== undefined &&
      inact.inactivityDays >= rules.inactivityDays
    ) {
      triggers.push('contractor_inactivity');
    }

    if (triggers.length === 0) continue;

    results.push({
      accountId: id,
      triggers,
      basis: {
        hrStatus: hr?.status ?? null,
        inactivityDays: inact?.inactivityDays ?? null,
        orphanedStatus: orphan?.orphanedStatus ?? null,
      },
    });
  }

  return results;
}
