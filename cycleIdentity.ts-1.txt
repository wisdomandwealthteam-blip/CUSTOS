/**
 * engines/cycleIdentity.ts
 *
 * NEW FILE, not one of the originally given engines/capabilities — needed
 * because artifact.executionContext (execution artifact model) requires
 * cycleId/episodeId, but execution runs BEFORE memory in the frozen
 * sequence, and memory previously generated these ids itself. Generating
 * them once, here, at the start of a cycle — before Diagnostics even runs —
 * and threading the SAME values through execution and memory is what
 * "coherence"/"no cross-engine drift" requires: two independently-generated
 * ids would never match.
 *
 * Id generation itself uses Date.now(), same as the originally-given
 * memoryEngine.ts stub already did — covered by section 12's "no randomness
 * except for IDs" exception, not a new category of impurity.
 */

export interface CycleIdentity {
  cycleId: string;
  episodeId: string;
}

export function generateCycleIdentity(): CycleIdentity {
  const now = Date.now();
  return {
    cycleId: `cycle-${now}`,
    episodeId: `episode-${now}`,
  };
}
