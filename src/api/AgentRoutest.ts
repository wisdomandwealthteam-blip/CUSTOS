import { Router } from 'express';
import { AgentInput } from '../contracts/AgentInput';
import { generateCycleIdentity } from '../engines/cycleIdentity';
import { runDiagnostics } from '../engines/diagnosticsEngine';
import { runReasoning } from '../engines/reasoningEngine';
import { runGovernance } from '../engines/governanceEngine';
import { runExecution } from '../engines/executionEngine';
import { writeMemoryEpisode, finalizeMemoryEpisode } from '../engines/memoryEngine';
import { runAutonomy } from '../engines/autonomyEngine';

const router = Router();

router.post('/agent/run', (req, res) => {
  const input: AgentInput = req.body;

  const { cycleId, episodeId } = generateCycleIdentity();

  const diag = runDiagnostics(input);
  const reasoning = runReasoning(diag, input.agentConfig.rules);
  const governance = runGovernance(reasoning);
  const execution = runExecution(governance, reasoning, input.environment, cycleId, episodeId);

  const preliminaryEpisode = writeMemoryEpisode(execution, input.environment, governance, cycleId, episodeId);

  const autonomy = runAutonomy(preliminaryEpisode);

  const episode = finalizeMemoryEpisode(preliminaryEpisode, autonomy);

  res.json({
    agentCycleReport: {
      cycleId: episode.cycleId,
      timestamp: input.environment.timestamp,
      capabilitiesActivated: autonomy.activatedCapabilities,
      risksDetected: reasoning.riskLevels,
      actionsAuthorized: governance.allowedActions,
      actionsBlocked: governance.blockedActions,
      governanceNotes: governance.governanceNotes,
    },
    agentMemoryEpisode: episode,
    agentAutonomyReport: autonomy,
  });
});

export default router;
