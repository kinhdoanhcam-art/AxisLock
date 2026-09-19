# AxisLock

AxisLock is a GenLayer role-boundary interface for the deployed
`RoleSeparationGuard` intelligent contract. It prevents one wallet from holding
roles whose natural-language responsibilities violate an immutable separation
policy.

## Live contract

- Network: GenLayer StudioNet (`61999`)
- Contract: `0xcABB03122773C299Bd0894A79fABb7d4b1cC2556`
- Contract version: `1.1`
- Explorer: <https://explorer-studio.genlayer.com/address/0xcABB03122773C299Bd0894A79fABb7d4b1cC2556>
- Source SHA-256: `7d3c6060d01b97efd426702c50d755f0dad3ba5b0f4a6eb4f4738ad748340b6f`

The technical contract name remains `RoleSeparationGuard`; **AxisLock** is the
product and interface name.

The exact deployed source is included at
[`contract/AxisLock.py`](./contract/AxisLock.py). The filename follows the
product name while the deployed Python class remains `RoleSeparationGuard`.

## What it does

1. Creates a workspace with an immutable separation policy and one to three
   initial role definitions.
2. Appends new roles and immutable role versions.
3. Assigns a first role deterministically.
4. Uses GenLayer validator consensus before assigning a second role to the same
   wallet.
5. Permanently locks a role-ID pair after a conflict verdict, preventing later
   rewording from bypassing the decision.
6. Exposes the complete role and assignment-attempt ledger for verification.

## Run locally

```bash
pnpm install
pnpm dev
```

Open the local URL printed by the development server. Reads work without a
wallet. Writes require an EVM-compatible wallet connected to StudioNet.

## Checks

```bash
pnpm lint
pnpm build
```

See [TESTING.md](./TESTING.md) for the manual contract-flow checklist.

## Deploy to Vercel

Import the GitHub repository and use the **Next.js** framework preset.

- Build command: `pnpm build` (or leave the detected default)
- Output directory: leave empty
- Install command: `pnpm install --frozen-lockfile` (or leave the detected default)

The production build writes the standard Next.js output to `.next`; do not set
the Vercel output directory to `dist`.
