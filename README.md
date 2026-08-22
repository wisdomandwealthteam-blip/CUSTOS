# arkheia-agent

25/25 tests passing this round (`src/tests/pipeline.test.ts`, full rewrite —
see below). All files compile clean under `tsc --strict` except
`api/agentRoutes.ts`/`api/server.ts` (need `express`/`@types/node`, no
network access here to install them — syntax-consistent, not
compiler-verified). Verified with a real end-to-end run, not just unit
tests: `cycleId`/`episodeId` match exactly between every execution artifact
and the final memory episode, `governanceDecisionId` is consistent across
all artifacts from one cycle.

## This round: memory indexing, execution artifacts, autonomy scheduling, action coherence

Four consecutive rule sets, some in real tension with each other and with
the frozen sequence. Reconciliations, not guesses:

**1. `autonomySummary` inside the memory episode vs. Memory running before
Autonomy (section 8).** Real conflict, not solved by reordering the frozen
sequence or by hidden state (both forbidden). Solved by splitting memory
into two functions: `writeMemoryEpisode()` still runs in its exact given
slot, computing everything derivable from execution+governance alone
(`identityAxis`/`triggerAxis`/`actionAxis`/`artifactAxis`, `executionSummary`,
`evidence`). `finalizeMemoryEpisode(episode, autonomy)` is a NEW function
that runs after autonomy completes and fills in `riskAxis`/`autonomySummary`
— an assembly step added after the fixed six-engine sequence finishes, not
a reordering of it.

**2. `executionContext.episodeId`/`cycleId` on every artifact vs. those ids
previously being generated inside `memoryEngine`, which runs after
execution.** Fixed by extracting id generation into a new file
(`cycleIdentity.ts`), called once at the very start of a cycle — before
Diagnostics — and threading the same two values through execution and
memory. Two independently-generated ids would never match, which is exactly
what "no cross-engine drift" forbids.

**3. `governanceDecisionId` is a new concept with no prior definition for
how it's generated.** Generated the same way `episodeId`/`cycleId` already
were (Date.now()-based) — the same "no randomness except for IDs" exception,
reused, not a new mechanism invented.

**4. Artifact structure corrected, not extended.** The execution artifact
model is FLAT (`targetId`/`reason`/`evidence` directly on the artifact) —
my prior round's nested `{artifactType, fields: {...}}` shape is gone.
`blocked_action_model` is now one artifact per blocked action (matching
`disable_account_model`'s shape), not the single summary object it used to
be. `no_action_model` is new: exactly one artifact, `targetId`/`evidence`
both `null`, emitted only when a cycle has zero triggers at all.

**5. The scheduling formula was given without an explicit combining
condition.** `riskDetected`/`actionOccurred`/`artifactProduced` are all
named booleans, but nothing states how they combine into the
`nextCycleScheduledAt` decision. Taking `artifactProduced` as a gate would
mean scheduling fires literally every cycle now, since `no_action_model`
guarantees at least one artifact always exists — which would defeat the
entire premise of `onRiskDetected`-gated scheduling. Kept `riskDetected`
(now precisely redefined: `triggerAxis` intersects `scanFor`) as the sole
gate; `actionOccurred`/`artifactProduced` are computed and available but
don't alter the schedule. Flagged in `autonomyEngine.ts`, not guessed.
`test_no_action_cycle_does_NOT_schedule` exists specifically to catch a
future change that accidentally makes this always-on.

**6. `evidence: {passwordLastChanged, stalePasswordDays}` from two rounds
ago is now explicitly confirmed as "the uniform capability basis object"** —
resolves the discrepancy I flagged then. No change needed; that flag can be
considered closed.

## Old README content below (previous rounds, still accurate for what it covers)

## Resolved: the `privileged_account` tension flagged last round

`privilegeGovernance` now fires `privileged_account` from an explicit
`privilegeMap[userId].privilegedAccountFlag` boolean field — not from
`privilegeLevel` alone. This doesn't contradict the earlier reference-
validated correction ("risk tags only from an explicit rule match, never
from `privilegeLevel` alone"); it's the missing explicit field that
correction said was required. `governancePolicy.allow.disable_account` and
`autonomyRules.riskScan.scanFor` both include it now, and it's live end to
end — a test confirms `privilegeLevel==="privileged"` alone still never
triggers anything, and a separate test confirms the explicit flag does.

Structural note: the definition given used a singular `{userId, trigger,
evidence}` shape; it's folded into the existing uniform `{accountId,
triggers: string[], basis}` structure every other capability uses, alongside
`privilege_change` in the same `PrivilegeTrigger` array. The trigger name,
firing condition, and evidence value are preserved exactly; only the
enclosing container stays consistent with the rest of the pipeline.

## Two signature changes from the given skeleton — flagged, not silent

The given skeleton's `runReasoning(diag)` and `runExecution(gov)` signatures
cannot carry data that the definitions you supplied afterward require:

- **`runReasoning(diag, rules)`** — `contractorGovernance`/
  `serviceAccountGovernance`/`trustDcGovernance` all need
  `agentConfig.rules`, which `DiagnosticsNormalized` never carries. Adding a
  hidden module-level variable instead would violate section 3's "no hidden
  state" — a real signature change was the only option that didn't trade one
  contract violation for another.
- **`runExecution(gov, reasoning, environment)`** — the confirmed
  `disable_account_model` artifact schema needs `evidence` (the trigger's
  `basis` object, which only exists in `ReasoningOutput`, not in
  `GovernanceDecision`'s plain action-descriptor strings) and `timestamp`
  (only in `environment`). Same reasoning: mechanically required by the
  schema you gave me, not a preference.

Both changes are additive only (no existing field removed or renamed) and
`agentRoutes.ts` was updated to pass the new arguments.

## `agentConfig.rules` added to `AgentInput`

You supplied `agentConfig.rules = {...}` as an explicit definition — added
verbatim to the `AgentInput` contract's `agentConfig` field. This is
incorporating a definition you gave me, not an invented field.

## What changed in each capability

- **`identityGovernance`**: now routes by `identityMap[id].category`/`type`
  — `category==="contractor"` goes to `contractorGovernance`,
  `category==="system"` or `type==="service"` goes to
  `serviceAccountGovernance`. No `identityMap` entry defaults here rather
  than being silently dropped. Trigger names updated to the real vocabulary
  (`identity_inactivity`/`identity_orphaned`/`identity_termination`).
- **`contractorGovernance`**: real implementation. Contractor identified via
  `identityMap.category==="contractor"` OR `hrMap.employmentType==="contractor"`
  (either counts). `contractor_termination` gated on
  `contractorRules.autoDisableOnTermination`. `contractor_orphaned` reuses
  `orphanedMap` (same signal as identity), ungated. `contractor_inactivity`
  uses a raw `inactivityDays` vs. `contractorRules.inactivityDays` threshold
  comparison — genuinely different mechanism from `identityGovernance`'s
  status-string check, and not in `governancePolicy.allow`, so it's
  detected/reported but always ends up blocked by governance. That's
  correct, not a bug — visibility without auto-approval.
- **`serviceAccountGovernance`**: real implementation for `service_orphaned`
  (reuses `orphanedMap`, gated on `serviceAccountRules.orphanedIfNoOwner`).
  **`service_stale_password` remains unimplemented** — `stalePasswordDays`
  is a real threshold, but no field anywhere (not `identityMap`, not
  `uacMap`, nowhere) carries a password-last-changed date to compare it
  against. Needs a field like `passwordLastChangedAt` added to a map schema.
- **`trustDcGovernance`**: REPLACED, not extended. The prior version's
  `trust_decommission`/`dc_decommission` checks were explicitly flagged last
  round as unverified guesses. Neither name appears anywhere in
  `governancePolicy` or `autonomyRules.riskScan.scanFor` — the real
  vocabulary is `trust_degraded`/`dc_replication_failure`, driven by
  `trustRules.degradedLevels`/`replicationFailureStates`. The old checks are
  gone, confirmed by a test (`trust_decommission/dc_decommission trigger
  names no longer produced`).
- **`privilegeGovernance`**: unchanged — `privilegeChanged===true` →
  `privilege_change`, now confirmed correct by
  `governancePolicy.block.privilege_change: "always"`.

## Resolved this round: `service_stale_password`

Fully implemented. `uacMap[accountId].passwordLastChanged` compared against
`environment.timestamp` (used as "currentTimestamp" — not sourced anywhere
in the given definition, chosen for consistency with every other "now" in
this pipeline) via `serviceAccountRules.stalePasswordDays`, in days.
`reasoningEngine`'s existing `DiagnosticsNormalized` parameter already
carried both `uacMap` and `environment` — no further engine-level signature
change needed, just a new argument to an existing call.

**One thing worth flagging rather than silently living with:** the given
evidence shape for this trigger was exactly `{passwordLastChanged,
stalePasswordDays}` — two fields. The actual artifact evidence also includes
`orphanedStatus` (`null` when irrelevant), because `serviceAccountGovernance`'s
`basis` object is uniformly shaped across both its triggers, matching every
other capability in this pipeline. It's a superset, not a wrong value — but
given how precisely this evidence shape was specified, it's called out
explicitly rather than assumed acceptable. Say if you want per-trigger scoped
evidence instead.

No longer any open trigger definitions from this project's list.

## Real governance policy, replacing the earlier fail-closed placeholder

`GOVERNANCE_POLICY` in `governanceEngine.ts` is now your actual policy: the
only defined action type is `disable_account`, allowed only for the seven
triggers explicitly listed in `governancePolicy.allow.disable_account`.
Everything else — `privilege_change`, both trust triggers, and any
undefined trigger — is blocked. The explicit `block` dict's other five
entries (`trust_repair`, `dc_promotion`, `dc_reset`,
`service_account_rotation`, `contractor_extension`) mostly document action
types no current capability actually proposes; they fall to the same
default-deny path regardless.

## Execution artifacts

`disable_account_model` now matches your schema exactly: `targetId`,
`reason` (the trigger name), `evidence` (the real `basis` object looked up
from `ReasoningOutput`), `timestamp` (`environment.timestamp`, kept
deterministic — no fresh `Date.now()` call here, unlike the memory episode
IDs, which the "no randomness except for IDs" exception explicitly covers).
A `blocked_actions_summary` artifact (not part of your given schema) is
still emitted so section 4's "execution produces artifacts" holds even on a
cycle where nothing was allowed.
