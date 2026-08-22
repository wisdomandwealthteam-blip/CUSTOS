/**
 * capabilities/privilegeGovernance.ts
 *
 * Ports the privilege-risk logic from interpretDiagnostics, with one
 * documented gap: the prior schema's rule-matching mechanism drew from
 * `environmentMetadata.privilegeRules`, explicitly supplied by the caller.
 * AgentInput has no equivalent rules source anywhere (agentConfig only has
 * cycleMode/capabilityFilters/memoryMode/rules). So the rule-match half of
 * the prior logic has NO input to run against here — riskTags stay empty
 * until a rules source is added. privilegeChanged is still checked (a
 * boolean field on the account record itself, not an external rule),
 * consistent with the validated logic.
 *
 * privileged_account: fires when privilegeMap[userId].privilegedAccountFlag
 * === true — an EXPLICIT, dedicated boolean field, not a derivation from
 * privilegeLevel. This resolves the tension flagged last round: reviving a
 * trigger from privilegeLevel alone would have contradicted the earlier
 * reference-validated correction ("risk tags only from an explicit rule
 * match, never from privilegeLevel alone"). This field is exactly that kind
 * of explicit signal, so it doesn't contradict that correction — it's the
 * missing explicit basis the correction said was required.
 *
 * Structural note: the definition given for this trigger used a singular
 * {userId, trigger, evidence} shape. Every other capability in this system
 * (identity/contractor/service/trust) uses a uniform {accountId, triggers:
 * string[], basis} array shape, and privilege_change already used that same
 * shape. privileged_account is folded into that existing structure — same
 * PrivilegeTrigger array, same basis object — rather than introducing a
 * one-off divergent shape. The trigger name, firing condition, and evidence
 * VALUE ({ privilegedAccountFlag: true }) are preserved exactly as given;
 * only the enclosing container stays consistent with the rest of the pipeline.
 */

export interface PrivilegeTrigger {
  accountId: string;
  triggers: string[];
  basis: {
    privilegeLevel: any;
    adminGroupMembership: any[];
    delegatedPermissions: any[];
    privilegedAccountFlag?: boolean;
  };
}

function recordId(obj: any): string | null {
  return obj?.accountId ?? obj?.id ?? null;
}

/** Pure function. */
export function runPrivilegeGovernance(privilegeMap: any): PrivilegeTrigger[] {
  const accounts = privilegeMap?.accounts ?? [];
  const results: PrivilegeTrigger[] = [];

  for (const acct of accounts) {
    const id = recordId(acct);
    if (!id) continue;

    const triggers: string[] = [];
    if (acct.privilegeChanged === true) {
      triggers.push('privilege_change');
    }
    if (acct.privilegedAccountFlag === true) {
      triggers.push('privileged_account');
    }

    if (triggers.length === 0) continue;

    const basis: PrivilegeTrigger['basis'] = {
      privilegeLevel: acct.privilegeLevel ?? null,
      adminGroupMembership: acct.adminGroupMembership ?? [],
      delegatedPermissions: acct.delegatedPermissions ?? [],
    };
    if (acct.privilegedAccountFlag === true) {
      basis.privilegedAccountFlag = true;
    }

    results.push({ accountId: id, triggers, basis });
  }

  return results;
}
