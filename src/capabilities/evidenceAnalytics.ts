/**
 * capabilities/evidenceAnalytics.ts
 *
 * NOT SPECIFIED. No purpose, metrics, or output shape for this capability
 * was ever given — unlike the other five, whose names at least imply a
 * clear domain (identity/privilege/service/contractor/trust governance),
 * "evidence analytics" could mean many different things (record counts?
 * coverage completeness? data quality scoring?) and picking one would be
 * inventing a capability behavior this contract forbids.
 *
 * What's implemented instead is the one thing that's unambiguous and
 * requires no interpretation: a deterministic COUNT of records present in
 * each map, with no judgment attached. This is reflection, not analytics —
 * flagged as a placeholder pending an actual specification, not presented
 * as the real capability.
 */

export interface EvidenceSummary {
  recordCounts: {
    identity: number;
    privilege: number;
    uac: number;
    orphaned: number;
    inactivity: number;
    hr: number;
    trust: number;
  };
}

function count(map: any, arrayKey: string): number {
  return Array.isArray(map?.[arrayKey]) ? map[arrayKey].length : 0;
}

// identityMap/hrMap are keyed objects (identityMap[userId] = {...}), not
// {accounts: [...]} arrays like the other five maps — confirmed by their
// schemas. A plain count() call would always read 0 for these; this counts
// object keys instead.
function countKeyed(map: any): number {
  return map && typeof map === 'object' ? Object.keys(map).length : 0;
}

/** Pure function. */
export function runEvidenceAnalytics(diag: {
  identityMap: any;
  privilegeMap: any;
  uacMap: any;
  orphanedMap: any;
  inactivityMap: any;
  hrMap: any;
  trustMap: any;
}): EvidenceSummary {
  return {
    recordCounts: {
      identity: countKeyed(diag.identityMap),
      privilege: count(diag.privilegeMap, 'accounts'),
      uac: count(diag.uacMap, 'accounts'),
      orphaned: count(diag.orphanedMap, 'accounts'),
      inactivity: count(diag.inactivityMap, 'accounts'),
      hr: countKeyed(diag.hrMap),
      trust: count(diag.trustMap, 'entities'),
    },
  };
}

/**
 * aggregateEvidence — extracts {targetId, reason, evidence} triples directly
 * from execution artifacts, for use as the memory episode's top-level
 * `evidence` field. Reads the FLAT artifact shape (targetId/reason/evidence
 * directly on the artifact) confirmed by the execution artifact model —
 * corrected from an earlier nested `fields.targetId`-style shape this
 * pipeline no longer uses. Pure reflection: no filtering, no judgment,
 * includes no_action_model entries too (targetId/evidence: null) for full
 * coherence with "every action must include targetId, reason, evidence" —
 * the action occurred (or didn't), and this reflects that either way.
 */
export interface EvidenceEntry {
  targetId: string | null;
  reason: string;
  evidence: any;
}

export function aggregateEvidence(artifacts: { targetId: string | null; reason: string; evidence: any }[]): EvidenceEntry[] {
  return artifacts.map((a) => ({ targetId: a.targetId, reason: a.reason, evidence: a.evidence }));
}
