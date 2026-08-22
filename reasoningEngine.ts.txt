import { DiagnosticsNormalized } from './diagnosticsEngine';
import { AgentInput } from '../contracts/AgentInput';
import { runIdentityGovernance } from '../capabilities/identityGovernance';
import { runPrivilegeGovernance } from '../capabilities/privilegeGovernance';
import { runTrustDcGovernance } from '../capabilities/trustDcGovernance';
import { runServiceAccountGovernance } from '../capabilities/serviceAccountGovernance';
import { runContractorGovernance } from '../capabilities/contractorGovernance';

export interface ReasoningOutput {
  identityTriggers: any[];
  privilegeTriggers: any[];
  serviceTriggers: any[];
  contractorTriggers: any[];
  trustTriggers: any[];
  riskLevels: any[];
}

type Rules = AgentInput['agentConfig']['rules'];

/**
 * SIGNATURE CHANGE FROM THE GIVEN SKELETON, FLAGGED EXPLICITLY: the original
 * signature was `runReasoning(diag: DiagnosticsNormalized)`. contractorRules/
 * serviceAccountRules/trustRules (agentConfig.rules) are REQUIRED by
 * contractorGovernance/serviceAccountGovernance/trustDcGovernance to do
 * anything at all — without them, those capabilities' gated checks always
 * evaluate false and never fire, silently. There is no way to honor the
 * now-confirmed rule definitions without this data reaching reasoning. This
 * is a data-flow necessity, not a preference — adding a hidden global/module-
 * level variable instead would violate section 3's "no hidden state" rule for
 * pure functions, which is worse. Still a real deviation from "preserve all
 * function signatures" — flagged here and in the response, not silently made.
 */
export function runReasoning(diag: DiagnosticsNormalized, rules: Rules): ReasoningOutput {
  const identityTriggers = runIdentityGovernance(diag.orphanedMap, diag.inactivityMap, diag.identityMap);
  const privilegeTriggers = runPrivilegeGovernance(diag.privilegeMap);
  const serviceTriggers = runServiceAccountGovernance(
    diag.identityMap,
    diag.orphanedMap,
    diag.uacMap,
    rules?.serviceAccountRules,
    diag.environment.timestamp
  );
  const contractorTriggers = runContractorGovernance(
    diag.identityMap,
    diag.hrMap,
    diag.orphanedMap,
    diag.inactivityMap,
    rules?.contractorRules
  );
  const trustTriggers = runTrustDcGovernance(diag.trustMap, rules?.trustRules);

  const riskLevels: any[] = [];
  for (const t of identityTriggers) riskLevels.push({ id: t.accountId, category: 'identity', triggers: t.triggers });
  for (const t of privilegeTriggers) riskLevels.push({ id: t.accountId, category: 'privilege', triggers: t.triggers });
  for (const t of serviceTriggers) riskLevels.push({ id: t.accountId, category: 'service', triggers: t.triggers });
  for (const t of contractorTriggers) riskLevels.push({ id: t.accountId, category: 'contractor', triggers: t.triggers });
  for (const t of trustTriggers) riskLevels.push({ id: t.entityId, category: 'trust', triggers: t.triggers });

  return {
    identityTriggers,
    privilegeTriggers,
    serviceTriggers,
    contractorTriggers,
    trustTriggers,
    riskLevels,
  };
}
