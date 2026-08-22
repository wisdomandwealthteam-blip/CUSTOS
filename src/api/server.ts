/**
 * api/server.ts — named in the original file tree but no content was ever
 * given for it. Minimal, standard Express bootstrap: mounts agentRoutes and
 * listens on a port. Nothing here is a contract decision (no engine logic,
 * no capability logic, no governance/autonomy behavior) — it's the
 * infrastructure needed to actually run the API described by the rest of
 * this codebase.
 */

import express from 'express';
import agentRoutes from './agentRoutes';

const app = express();
app.use(express.json());
app.use('/', agentRoutes);

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

app.listen(PORT, () => {
  console.log(`arkheia-agent listening on port ${PORT}`);
});

export default app;
