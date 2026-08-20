export interface AgentInput {
  diagnostics: {
    identityMap: any;
    privilegeMap: any;
    uacMap: any;
    orphanedMap: any;
    inactivityMap: any;
    hrMap: any;
    trustMap: any;
  };
  agentConfig: {
    cycleMode: 'manual' | 'autonomous';
    capabilityFilters?: string[];
    memoryMode: 'full' | 'summary';
    // Added per explicit definition supplied by the user ("agentConfig.rules
    // = {...}") — not an invented field. contractorGovernance/
    // serviceAccountGovernance/trustDcGovernance all require this data and
    // have no other path to it.
    rules?: {
      serviceAccountRules?: {
        stalePasswordDays?: number;
        orphanedIfNoOwner?: boolean;
      };
      contractorRules?: {
        inactivityDays?: number;
        autoDisableOnTermination?: boolean;
      };
      trustRules?: {
        degradedLevels?: string[];
        replicationFailureStates?: string[];
      };
    };
  };
  environment: {
    tenantId: string;
    timestamp: string;
    region: string;
  };
}
