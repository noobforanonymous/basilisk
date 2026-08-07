# Basilisk ground-truth laboratory

This local lab is deliberately vulnerable and must never be exposed to an external network. It implements deterministic vulnerable and secure AI targets, tenant authorization boundaries, fake tool side effects, WebSocket behavior, and hostile response cases.

Start it:

```bash
docker compose -f lab/docker-compose.yml up --build
```

Run a bounded scan:

```bash
basilisk scan http://127.0.0.1:8765/vulnerable/v1/chat/completions \
  --provider custom --mode quick --no-evolve --skip-recon \
  --isolated-environment --module injection.direct --output json
```

The fake SSRF, SQL, and shell tools never access a network, database,
filesystem, or process. `ground_truth.json` versions 46 scenarios spanning
secure/vulnerable HTTP behavior, valid and invalid authorization states,
WebSocket behavior, and hostile responses. Benchmark runners compare scanner
output to those labels.

Lab credentials are intentionally public test values: `user-a-valid`, `user-b-valid`, `admin-valid`, `user-a-expired`, and `user-a-revoked`.
