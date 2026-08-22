import { AgentInput } from '../contracts/AgentInput';

export interface DiagnosticsNormalized {
  identityMap: any;
  privilegeMap: any;
  uacMap: any;
  orphanedMap: any;
  inactivityMap: any;
  hrMap: any;
  trustMap: any;
  environment: AgentInput['environment'];
}

export function runDiagnostics(input: AgentInput): DiagnosticsNormalized {
  return {
    identityMap: input.diagnostics.identityMap,
    privilegeMap: input.diagnostics.privilegeMap,
    uacMap: input.diagnostics.uacMap,
    orphanedMap: input.diagnostics.orphanedMap,
    inactivityMap: input.diagnostics.inactivityMap,
    hrMap: input.diagnostics.hrMap,
    trustMap: input.diagnostics.trustMap,
    environment: input.environment,
  };
}
