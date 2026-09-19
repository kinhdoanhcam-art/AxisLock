# AxisLock testing

## Automated checks

Run:

```bash
pnpm lint
pnpm build
```

Both commands must finish successfully before deployment.

## Read-only smoke test

1. Open **Overview**.
2. Confirm the interface reads contract `v1.1` from StudioNet.
3. Confirm the live metrics show workspace count `0`, pair limit `2`, and holder
   cap `2` on a fresh deployment.
4. Open every navigation item and confirm each operational screen renders.
5. Open **Proof** and verify the contract address and explorer link.

## Write-path test

1. Connect an EVM-compatible wallet on chain `61999`.
2. Create a workspace with an immutable policy and two roles.
3. Register an additional role and a new version of an existing role.
4. Assign one role to a holder; confirm `FIRST_ROLE_ASSIGNED` in **Ledger**.
5. Assign a compatible second role; confirm `ASSIGNED_COMPATIBLE`.
6. In a separate holder test, assign two roles that clearly violate the policy;
   confirm `BLOCKED_CONFLICT` and a `ROLE_PAIR_CONFLICT` verdict.
7. Try that conflicting role pair again after registering a new wording version;
   confirm the learned conflict remains locked.
8. Revoke an active role and confirm the holder and workspace counters update.

Never resubmit a transaction while its current hash is still pending. AxisLock
waits for the StudioNet transaction status to reach `FINALIZED`.

