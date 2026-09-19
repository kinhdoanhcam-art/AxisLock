"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  Check,
  Clipboard,
  ExternalLink,
  FileCheck2,
  GitCompareArrows,
  Layers3,
  LoaderCircle,
  LockKeyhole,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  UserRoundCheck,
  Wallet,
  X,
} from "lucide-react";
import { createClient } from "genlayer-js";
import { studionet } from "genlayer-js/chains";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Toaster } from "@/components/ui/sonner";

const CONTRACT_ADDRESS = "0xcABB03122773C299Bd0894A79fABb7d4b1cC2556" as const;
const RPC_URL = "https://studio.genlayer.com/api";
const EXPLORER_URL = `https://explorer-studio.genlayer.com/address/${CONTRACT_ADDRESS}`;
const SOURCE_SHA = "7d3c6060d01b97efd426702c50d755f0dad3ba5b0f4a6eb4f4738ad748340b6f";
const DEPLOY_TX = "0xe809aa1d6e1a6b74b99976b91d4ed7636701a379ac933d64611471972aed9612";
const chain = { ...studionet, rpcUrls: { default: { http: [RPC_URL] } } };
const readClient = createClient({ chain });

type EthereumProvider = {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
};

type Config = {
  name: string;
  version: string;
  workspace_count: number;
  max_roles_per_address: number;
  max_roles_per_workspace: number;
  max_versions_per_role: number;
  role_pair_eval_limit: number;
  conflict_locked_by_role_pair: boolean;
  separation_policy_mutable: boolean;
  role_versions_mutable: boolean;
  semantic_verdicts: string[];
};

type Workspace = {
  workspace_id: number;
  authority: string;
  separation_policy: string;
  role_count: number;
  attempt_count: number;
  conflict_blocked_count: number;
  active_assignment_count: number;
};

type Role = {
  workspace_id: number;
  role_id: number;
  name: string;
  current_version: number;
};

type RoleVersion = {
  workspace_id: number;
  role_id: number;
  role_name: string;
  role_version: number;
  definition_text: string;
  active_holder_count: number;
  is_current: boolean;
};

type LedgerRole = Role & { version: RoleVersion };

type Attempt = {
  attempt_id: number;
  holder: string;
  candidate_role_id: number;
  candidate_role_version: number;
  existing_role_id: number;
  existing_role_version: number;
  verdict: string;
  outcome: string;
  used_cache: boolean;
};

type Holder = {
  workspace_id: number;
  holder: string;
  active_count: number;
  role1_id: number;
  role1_version: number;
  role2_id: number;
  role2_version: number;
};

type Ledger = { workspace: Workspace; roles: LedgerRole[]; attempts: Attempt[] };
type InitialRole = { name: string; definition: string };

type ModelContext = {
  registerTool(
    tool: {
      name: string;
      title: string;
      description: string;
      inputSchema: Record<string, unknown>;
      annotations?: { readOnlyHint?: boolean; untrustedContentHint?: boolean };
      execute(input: unknown): unknown | Promise<unknown>;
    },
    options?: { signal?: AbortSignal },
  ): void | Promise<void>;
};

declare global {
  interface Window { ethereum?: EthereumProvider }
  interface Document { modelContext?: ModelContext }
}

const nav = ["Overview", "Workspace", "Roles", "Assign", "Ledger", "Proof"] as const;
const compact = (value: string) => `${value.slice(0, 6)}…${value.slice(-5)}`;
const errorMessage = (error: unknown) => error instanceof Error ? error.message : String(error);

function positiveInteger(value: string, label: string) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) throw new Error(`${label} must be a positive integer.`);
  return parsed;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return <label className="field"><span>{label}{hint ? <small>{hint}</small> : null}</span>{children}</label>;
}

function StatusPanel({ status, hash }: { status: string; hash: string }) {
  if (!status && !hash) return null;
  return (
    <div className="status-panel" aria-live="polite">
      <span><small>LATEST OPERATION</small><strong>{status}</strong></span>
      {hash ? <code>{compact(hash)}</code> : <LoaderCircle className="spin" />}
    </div>
  );
}

export default function Home() {
  const [active, setActive] = useState<(typeof nav)[number]>("Overview");
  const [config, setConfig] = useState<Config | null>(null);
  const [loading, setLoading] = useState(true);
  const [account, setAccount] = useState("");
  const [txStatus, setTxStatus] = useState("");
  const [txHash, setTxHash] = useState("");

  const [policy, setPolicy] = useState("The wallet that proposes or initiates a sensitive action must remain independent from the wallet that reviews, approves, or audits that same action.");
  const [initialRoles, setInitialRoles] = useState<InitialRole[]>([
    { name: "Initiator", definition: "Creates and submits sensitive operational requests for approval." },
    { name: "Approver", definition: "Independently reviews and approves or rejects submitted sensitive requests." },
  ]);

  const [roleWorkspace, setRoleWorkspace] = useState("1");
  const [roleName, setRoleName] = useState("");
  const [roleDefinition, setRoleDefinition] = useState("");
  const [versionWorkspace, setVersionWorkspace] = useState("1");
  const [versionRole, setVersionRole] = useState("1");
  const [versionDefinition, setVersionDefinition] = useState("");

  const [assignWorkspace, setAssignWorkspace] = useState("1");
  const [holderAddress, setHolderAddress] = useState("");
  const [assignRoleId, setAssignRoleId] = useState("1");
  const [holder, setHolder] = useState<Holder | null>(null);
  const [holderLoading, setHolderLoading] = useState(false);

  const [ledgerWorkspace, setLedgerWorkspace] = useState("1");
  const [ledger, setLedger] = useState<Ledger | null>(null);
  const [ledgerLoading, setLedgerLoading] = useState(false);

  const loadConfig = useCallback(async () => {
    setLoading(true);
    try {
      const result = (await readClient.readContract({
        address: CONTRACT_ADDRESS,
        functionName: "get_config",
        args: [],
        transactionHashVariant: "latest-final",
      })) as Config;
      setConfig(result);
    } catch (error) {
      toast.error("Could not read StudioNet", { description: errorMessage(error) });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadConfig(), 0);
    return () => window.clearTimeout(timer);
  }, [loadConfig]);

  const connectWallet = useCallback(async () => {
    if (!window.ethereum) throw new Error("No EVM-compatible wallet was found in this browser.");
    const accounts = (await window.ethereum.request({ method: "eth_requestAccounts" })) as string[];
    if (!accounts[0]) throw new Error("Wallet connection was not approved.");
    const chainHex = (await window.ethereum.request({ method: "eth_chainId" })) as string;
    if (Number(BigInt(chainHex)) !== 61999) {
      toast.warning("Wrong wallet network", { description: "Switch to GenLayer StudioNet (chain ID 61999) before writing." });
    }
    setAccount(accounts[0]);
    toast.success("Wallet connected", { description: compact(accounts[0]) });
    return accounts[0];
  }, []);

  const waitForFinal = useCallback(async (hash: string) => {
    const started = Date.now();
    while (Date.now() - started < 10 * 60 * 1000) {
      const response = await fetch(RPC_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getTransactionByHash", params: [hash] }),
      });
      const payload = (await response.json()) as { result?: { status?: string } };
      const status = payload.result?.status;
      if (status) setTxStatus(status);
      if (status === "FINALIZED") return;
      if (status === "CANCELED" || status === "UNDETERMINED") throw new Error(`Transaction ended with status ${status}.`);
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
    throw new Error("Confirmation is taking longer than expected. Keep the transaction hash and do not resubmit yet.");
  }, []);

  const write = useCallback(async (functionName: string, args: unknown[], success: string) => {
    setTxHash("");
    setTxStatus("PREPARING");
    try {
      const wallet = account || await connectWallet();
      if (!window.ethereum) throw new Error("Wallet provider unavailable.");
      const client = createClient({ chain, account: wallet as `0x${string}`, provider: window.ethereum as never });
      const hash = await client.writeContract({ address: CONTRACT_ADDRESS, functionName, args, value: 0n, leaderOnly: false });
      setTxHash(hash);
      setTxStatus("SUBMITTED");
      toast.info("Transaction submitted", { description: compact(hash) });
      await waitForFinal(hash);
      setTxStatus("FINALIZED");
      toast.success(success, { description: compact(hash) });
      await loadConfig();
      return hash;
    } catch (error) {
      setTxStatus("STOPPED");
      toast.error("Operation stopped", { description: errorMessage(error) });
      throw error;
    }
  }, [account, connectWallet, loadConfig, waitForFinal]);

  const createWorkspace = async () => {
    try {
      if (!policy.trim()) throw new Error("Enter a separation policy.");
      if (!initialRoles.length || initialRoles.some((role) => !role.name.trim() || !role.definition.trim())) throw new Error("Every initial role needs a name and definition.");
      const nextId = (config?.workspace_count ?? 0) + 1;
      await write("create_workspace", [policy, JSON.stringify(initialRoles)], "Workspace boundary finalized");
      const id = String(nextId);
      setRoleWorkspace(id); setVersionWorkspace(id); setAssignWorkspace(id); setLedgerWorkspace(id);
    } catch (error) {
      if (txStatus !== "STOPPED") toast.error(errorMessage(error));
    }
  };

  const registerRole = async () => {
    try {
      if (!roleName.trim() || !roleDefinition.trim()) throw new Error("Enter a role name and definition.");
      await write("register_role", [positiveInteger(roleWorkspace, "Workspace ID"), roleName, roleDefinition], "Role registered");
      setRoleName(""); setRoleDefinition("");
    } catch (error) { if (txStatus !== "STOPPED") toast.error(errorMessage(error)); }
  };

  const registerVersion = async () => {
    try {
      if (!versionDefinition.trim()) throw new Error("Enter a new immutable role definition.");
      await write("register_role_version", [positiveInteger(versionWorkspace, "Workspace ID"), positiveInteger(versionRole, "Role ID"), versionDefinition], "Role version registered");
      setVersionDefinition("");
    } catch (error) { if (txStatus !== "STOPPED") toast.error(errorMessage(error)); }
  };

  const changeAssignment = async (mode: "assign_role" | "revoke_role") => {
    try {
      if (!/^0x[a-fA-F0-9]{40}$/.test(holderAddress)) throw new Error("Enter a valid 0x holder address.");
      await write(mode, [positiveInteger(assignWorkspace, "Workspace ID"), holderAddress, positiveInteger(assignRoleId, "Role ID")], mode === "assign_role" ? "Assignment decision finalized" : "Role revoked");
      await inspectHolder();
    } catch (error) { if (txStatus !== "STOPPED") toast.error(errorMessage(error)); }
  };

  const inspectHolder = useCallback(async () => {
    if (!/^0x[a-fA-F0-9]{40}$/.test(holderAddress)) throw new Error("Enter a valid 0x holder address.");
    setHolderLoading(true);
    try {
      const result = (await readClient.readContract({ address: CONTRACT_ADDRESS, functionName: "get_holder", args: [positiveInteger(assignWorkspace, "Workspace ID"), holderAddress], transactionHashVariant: "latest-final" })) as Holder;
      setHolder(result);
      return result;
    } catch (error) {
      toast.error("Holder could not be read", { description: errorMessage(error) });
      throw error;
    } finally { setHolderLoading(false); }
  }, [assignWorkspace, holderAddress]);

  const loadLedger = useCallback(async (workspaceOverride?: number) => {
    const wid = workspaceOverride ?? positiveInteger(ledgerWorkspace, "Workspace ID");
    setLedgerLoading(true);
    try {
      const workspace = (await readClient.readContract({ address: CONTRACT_ADDRESS, functionName: "get_workspace", args: [wid], transactionHashVariant: "latest-final" })) as Workspace;
      const roleRows = await Promise.all(Array.from({ length: workspace.role_count }, async (_, index) => {
        const roleId = index + 1;
        const role = (await readClient.readContract({ address: CONTRACT_ADDRESS, functionName: "get_role", args: [wid, roleId], transactionHashVariant: "latest-final" })) as Role;
        const version = (await readClient.readContract({ address: CONTRACT_ADDRESS, functionName: "get_role_version", args: [wid, roleId, role.current_version], transactionHashVariant: "latest-final" })) as RoleVersion;
        return { ...role, version };
      }));
      const attempts = workspace.attempt_count
        ? (await readClient.readContract({ address: CONTRACT_ADDRESS, functionName: "get_attempts", args: [wid, 1, Math.min(workspace.attempt_count, 50)], transactionHashVariant: "latest-final" })) as Attempt[]
        : [];
      const next = { workspace, roles: roleRows, attempts };
      setLedgerWorkspace(String(wid)); setLedger(next);
      return next;
    } catch (error) {
      toast.error("Workspace could not be loaded", { description: errorMessage(error) });
      throw error;
    } finally { setLedgerLoading(false); }
  }, [ledgerWorkspace]);

  useEffect(() => {
    const context = document.modelContext;
    if (!context?.registerTool) return;
    const lifecycle = new AbortController();
    const register = (tool: Parameters<ModelContext["registerTool"]>[0]) => void Promise.resolve(context.registerTool(tool, { signal: lifecycle.signal })).catch(() => undefined);
    register({
      name: "inspect_axislock_workspace",
      title: "Inspect AxisLock workspace",
      description: "Read a finalized role-separation workspace, its current role versions, and assignment decisions.",
      inputSchema: { type: "object", properties: { workspaceId: { type: "integer", minimum: 1 } }, required: ["workspaceId"], additionalProperties: false },
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      async execute(input) {
        const workspaceId = Number((input as { workspaceId?: unknown }).workspaceId);
        if (!Number.isInteger(workspaceId) || workspaceId < 1) throw new Error("workspaceId must be a positive integer");
        setActive("Ledger");
        return loadLedger(workspaceId);
      },
    });
    register({
      name: "stage_axislock_workspace",
      title: "Stage AxisLock workspace",
      description: "Populate a separation policy and initial roles for user review without submitting a transaction.",
      inputSchema: {
        type: "object",
        properties: {
          policy: { type: "string", minLength: 1, maxLength: 3000 },
          roles: { type: "array", minItems: 1, maxItems: 3, items: { type: "object", properties: { name: { type: "string" }, definition: { type: "string" } }, required: ["name", "definition"] } },
        },
        required: ["policy", "roles"], additionalProperties: false,
      },
      annotations: { readOnlyHint: false, untrustedContentHint: true },
      execute(input) {
        const value = input as { policy?: unknown; roles?: unknown };
        if (typeof value.policy !== "string" || !Array.isArray(value.roles)) throw new Error("A policy and one to three roles are required");
        setPolicy(value.policy); setInitialRoles(value.roles as InitialRole[]); setActive("Workspace");
        return { staged: true, submitted: false };
      },
    });
    register({
      name: "stage_axislock_assignment",
      title: "Stage AxisLock assignment",
      description: "Populate an assignment for user review without connecting a wallet or submitting it.",
      inputSchema: { type: "object", properties: { workspaceId: { type: "integer", minimum: 1 }, holder: { type: "string", pattern: "^0x[a-fA-F0-9]{40}$" }, roleId: { type: "integer", minimum: 1 } }, required: ["workspaceId", "holder", "roleId"], additionalProperties: false },
      annotations: { readOnlyHint: false, untrustedContentHint: true },
      execute(input) {
        const value = input as { workspaceId?: unknown; holder?: unknown; roleId?: unknown };
        if (!Number.isInteger(Number(value.workspaceId)) || typeof value.holder !== "string" || !Number.isInteger(Number(value.roleId))) throw new Error("Valid workspace, holder, and role values are required");
        setAssignWorkspace(String(value.workspaceId)); setHolderAddress(value.holder); setAssignRoleId(String(value.roleId)); setActive("Assign");
        return { staged: true, submitted: false };
      },
    });
    return () => lifecycle.abort();
  }, [loadLedger]);

  const metrics = useMemo(() => [
    ["WORKSPACES", loading ? "—" : String(config?.workspace_count ?? 0), "finalized scopes"],
    ["PAIR LIMIT", config ? String(config.role_pair_eval_limit) : "—", "model evaluations"],
    ["HOLDER CAP", config ? String(config.max_roles_per_address) : "—", "active roles"],
    ["SOURCE", "VERIFIED", `${SOURCE_SHA.slice(0, 7)}…${SOURCE_SHA.slice(-5)}`],
  ], [config, loading]);

  const copy = async (value: string, label: string) => {
    await navigator.clipboard.writeText(value);
    toast.success(`${label} copied`);
  };

  return (
    <main className="axis-shell">
      <Toaster position="bottom-right" richColors closeButton />
      <header className="topbar">
        <button className="brand" onClick={() => setActive("Overview")} aria-label="AxisLock overview">
          <span className="brand-mark"><LockKeyhole size={19} /></span>
          <span><strong>AxisLock</strong><small>ROLE BOUNDARY SYSTEM</small></span>
        </button>
        <nav className="nav" aria-label="Primary navigation">
          {nav.map((item, index) => <button key={item} className={active === item ? "active" : ""} onClick={() => setActive(item)}><span>{String(index + 1).padStart(2, "0")}</span>{item}</button>)}
        </nav>
        <div className="top-actions">
          <a className="contract-pill" href={EXPLORER_URL} target="_blank" rel="noreferrer"><i />{compact(CONTRACT_ADDRESS)}</a>
          <Button className="wallet-button" onClick={() => void connectWallet().catch((error) => toast.error("Wallet connection stopped", { description: errorMessage(error) }))}><Wallet />{account ? compact(account) : "Connect"}</Button>
        </div>
      </header>

      <div className="network-strip"><span><i /> STUDIONET / 61999</span><span>CONTRACT v{config?.version ?? "1.1"}</span><span className="strip-note">Immutable policy · versioned roles · pairwise consensus</span></div>

      {active === "Overview" && (
        <div className="page-frame">
          <section className="hero-grid">
            <div className="hero-copy">
              <span className="eyebrow">GENLAYER / AUTHORITY SEPARATION</span>
              <h1>Keep power<br /><em>off one axis.</em></h1>
              <p>Define operational roles, assign them to wallets, and stop incompatible authority from concentrating in one holder. Every decision remains inspectable on-chain.</p>
              <div className="hero-actions"><Button size="lg" className="primary-action" onClick={() => setActive("Workspace")}>Define a boundary <ArrowRight /></Button><Button size="lg" variant="outline" className="secondary-action" onClick={() => setActive("Ledger")}>Inspect decisions</Button></div>
            </div>
            <div className="axis-map" aria-label="Role separation diagram">
              <div className="grid-layer" /><span className="map-kicker">AUTHORITY MAP / SAME HOLDER</span><div className="axis horizontal" /><div className="axis vertical" />
              <div className="quadrant q1"><span>ROLE A</span><strong>Initiate</strong><small>ACTIVE</small></div><div className="quadrant q2"><span>ROLE B</span><strong>Review</strong><small>PROPOSED</small></div>
              <div className="lock-core"><LockKeyhole /><strong>AXISLOCK</strong><small>PAIR CHECK</small></div><div className="verdict-chip"><ShieldCheck /> CONFLICT BLOCKED</div>
            </div>
          </section>
          <section className="metric-grid" aria-label="Live contract summary">{metrics.map(([label, value, detail]) => <article key={label}><span>{label}</span><strong>{value}</strong><small>{detail}</small></article>)}</section>
          <section className="rule-grid"><article><span>01 / DEFINE</span><h2>Policy comes first.</h2><p>The workspace locks its separation rule before any role is assigned.</p></article><article><span>02 / COMPARE</span><h2>Meaning, not labels.</h2><p>Validators compare complete role definitions against the immutable boundary.</p></article><article><span>03 / ENFORCE</span><h2>Conflict stays locked.</h2><p>A learned role-pair conflict survives later wording and version changes.</p></article></section>
        </div>
      )}

      {active === "Workspace" && (
        <div className="page-frame operational-page">
          <section className="module-heading"><div><span className="eyebrow">01 / BOUNDARY DEFINITION</span><h1>Lock the rule<br />before the roles.</h1></div><p>A workspace belongs to its creating wallet. Its separation policy never changes; each initial role begins at immutable version 1.</p></section>
          <section className="form-layout">
            <div className="form-card wide-card">
              <div className="card-index">W</div><Field label="Separation policy" hint={`${policy.length} / 3000`}><Textarea value={policy} maxLength={3000} onChange={(e) => setPolicy(e.target.value)} rows={6} /></Field>
              <div className="roles-head"><div><strong>Initial roles</strong><small>1–3 roles are created with the workspace</small></div>{initialRoles.length < 3 && <Button variant="outline" onClick={() => setInitialRoles((current) => [...current, { name: "", definition: "" }])}><Plus /> Add role</Button>}</div>
              <div className="role-editor-list">{initialRoles.map((role, index) => <div className="role-editor" key={index}><span>{String(index + 1).padStart(2, "0")}</span><Input aria-label={`Role ${index + 1} name`} placeholder="Role name" value={role.name} onChange={(e) => setInitialRoles((current) => current.map((item, i) => i === index ? { ...item, name: e.target.value } : item))} /><Textarea aria-label={`Role ${index + 1} definition`} placeholder="Describe the authority and responsibility…" value={role.definition} onChange={(e) => setInitialRoles((current) => current.map((item, i) => i === index ? { ...item, definition: e.target.value } : item))} rows={3} />{initialRoles.length > 1 && <button className="icon-button" onClick={() => setInitialRoles((current) => current.filter((_, i) => i !== index))} aria-label={`Remove role ${index + 1}`}><Trash2 /></button>}</div>)}</div>
              <Button className="submit-action" onClick={() => void createWorkspace()}><LockKeyhole /> Create immutable workspace</Button><StatusPanel status={txStatus} hash={txHash} />
            </div>
            <aside className="side-stack"><article><span>AUTHORITY</span><h3>Creator-controlled</h3><p>Only the workspace authority can add role versions, assign roles, or revoke them.</p></article><article><span>BOUNDARY</span><h3>Immutable policy</h3><p>Policy text is fixed at creation, so later assignment decisions share the same rule.</p></article><article><span>START SMALL</span><h3>One to three roles</h3><p>Additional roles can be registered later without changing the boundary.</p></article></aside>
          </section>
        </div>
      )}

      {active === "Roles" && (
        <div className="page-frame operational-page">
          <section className="module-heading"><div><span className="eyebrow">02 / ROLE REGISTRY</span><h1>Version authority.<br />Never overwrite it.</h1></div><p>Role names stay stable while every definition update becomes a new immutable version. Active assignments keep the version they received.</p></section>
          <section className="dual-panels">
            <div className="form-card"><div className="panel-title"><Plus /><div><span>NEW ROLE</span><h2>Register another axis</h2></div></div><div className="two-fields"><Field label="Workspace ID"><Input inputMode="numeric" value={roleWorkspace} onChange={(e) => setRoleWorkspace(e.target.value)} /></Field><Field label="Role name"><Input placeholder="Auditor" value={roleName} maxLength={120} onChange={(e) => setRoleName(e.target.value)} /></Field></div><Field label="Role definition" hint={`${roleDefinition.length} / 3000`}><Textarea rows={7} maxLength={3000} placeholder="State exactly what this role may do…" value={roleDefinition} onChange={(e) => setRoleDefinition(e.target.value)} /></Field><Button className="submit-action" onClick={() => void registerRole()}>Register role <ArrowRight /></Button></div>
            <div className="form-card violet-card"><div className="panel-title"><Layers3 /><div><span>NEW VERSION</span><h2>Preserve a role revision</h2></div></div><div className="two-fields"><Field label="Workspace ID"><Input inputMode="numeric" value={versionWorkspace} onChange={(e) => setVersionWorkspace(e.target.value)} /></Field><Field label="Role ID"><Input inputMode="numeric" value={versionRole} onChange={(e) => setVersionRole(e.target.value)} /></Field></div><Field label="New definition" hint={`${versionDefinition.length} / 3000`}><Textarea rows={7} maxLength={3000} placeholder="Write the complete replacement definition…" value={versionDefinition} onChange={(e) => setVersionDefinition(e.target.value)} /></Field><Button className="submit-action violet-action" onClick={() => void registerVersion()}>Register immutable version <Layers3 /></Button></div>
          </section><StatusPanel status={txStatus} hash={txHash} />
        </div>
      )}

      {active === "Assign" && (
        <div className="page-frame operational-page">
          <section className="module-heading"><div><span className="eyebrow">03 / HOLDER CONTROL</span><h1>Assign only after<br />the pair agrees.</h1></div><p>The first role is deterministic. A second role invokes validator consensus against the workspace policy; conflicts are blocked and remembered.</p></section>
          <section className="form-layout assign-layout">
            <div className="form-card wide-card"><div className="card-index">A</div><div className="three-fields"><Field label="Workspace ID"><Input inputMode="numeric" value={assignWorkspace} onChange={(e) => setAssignWorkspace(e.target.value)} /></Field><Field label="Holder address"><Input placeholder="0x…" value={holderAddress} onChange={(e) => setHolderAddress(e.target.value)} /></Field><Field label="Role ID"><Input inputMode="numeric" value={assignRoleId} onChange={(e) => setAssignRoleId(e.target.value)} /></Field></div><div className="assignment-actions"><Button className="submit-action" onClick={() => void changeAssignment("assign_role")}><UserRoundCheck /> Assign current version</Button><Button variant="outline" className="danger-action" onClick={() => void changeAssignment("revoke_role")}><X /> Revoke role</Button><Button variant="outline" className="inspect-action" onClick={() => void inspectHolder().catch(() => undefined)}><Search /> Inspect holder</Button></div><StatusPanel status={txStatus} hash={txHash} /></div>
            <aside className="holder-card"><div className="panel-title"><GitCompareArrows /><div><span>HOLDER STATE</span><h2>{holderLoading ? "Reading…" : holder ? compact(holder.holder) : "Not loaded"}</h2></div></div>{holder ? <><div className="holder-count"><strong>{holder.active_count}</strong><span>ACTIVE<br />ROLES</span></div><div className="slot"><span>SLOT 01</span><strong>{holder.role1_id ? `Role ${holder.role1_id} · v${holder.role1_version}` : "EMPTY"}</strong></div><div className="slot"><span>SLOT 02</span><strong>{holder.role2_id ? `Role ${holder.role2_id} · v${holder.role2_version}` : "EMPTY"}</strong></div></> : <p>Enter a workspace and holder address, then inspect the finalized state before assigning.</p>}</aside>
          </section>
          <section className="verdict-grid"><article className="compatible"><span>ROLE_PAIR_COMPATIBLE</span><h3>Assignment activates</h3><p>The second role does not violate the locked separation policy.</p></article><article className="conflict"><span>ROLE_PAIR_CONFLICT</span><h3>Assignment stays blocked</h3><p>The role-ID pair is locked as conflicting, including future wording versions.</p></article></section>
        </div>
      )}

      {active === "Ledger" && (
        <div className="page-frame operational-page">
          <section className="ledger-heading"><div><span className="eyebrow">04 / FINALIZED STATE</span><h1>Read every boundary decision.</h1></div><div className="load-row"><Input aria-label="Workspace ID to load" inputMode="numeric" value={ledgerWorkspace} onChange={(e) => setLedgerWorkspace(e.target.value)} /><Button className="submit-action" onClick={() => void loadLedger()}>{ledgerLoading ? <LoaderCircle className="spin" /> : <RefreshCw />} Load workspace</Button></div></section>
          {ledger ? <>
            <section className="ledger-metrics"><article><span>WORKSPACE</span><strong>#{ledger.workspace.workspace_id}</strong><small>{compact(ledger.workspace.authority)}</small></article><article><span>ROLES</span><strong>{ledger.workspace.role_count}</strong><small>versioned definitions</small></article><article><span>ACTIVE</span><strong>{ledger.workspace.active_assignment_count}</strong><small>holder assignments</small></article><article><span>BLOCKED</span><strong>{ledger.workspace.conflict_blocked_count}</strong><small>semantic conflicts</small></article></section>
            <div className="policy-band"><span>IMMUTABLE POLICY</span><p>{ledger.workspace.separation_policy}</p></div>
            <section className="ledger-columns"><div><div className="section-title"><Layers3 /><span><strong>Roles</strong><small>Current immutable versions</small></span></div><div className="record-list">{ledger.roles.map((role) => <article className="record-card" key={role.role_id}><div><span>ROLE {String(role.role_id).padStart(2, "0")}</span><em>v{role.current_version}</em></div><h3>{role.name}</h3><p>{role.version.definition_text}</p><small>{role.version.active_holder_count} active holders</small></article>)}</div></div><div><div className="section-title"><GitCompareArrows /><span><strong>Assignment attempts</strong><small>Deterministic + semantic outcomes</small></span></div><div className="record-list">{ledger.attempts.length ? ledger.attempts.map((attempt) => <article className="record-card attempt-card" key={attempt.attempt_id}><div><span>ATTEMPT {String(attempt.attempt_id).padStart(2, "0")}</span><em className={attempt.outcome.includes("BLOCKED") ? "blocked" : "allowed"}>{attempt.outcome}</em></div><h3>{compact(attempt.holder)}</h3><p>Role {attempt.existing_role_id || "—"} → Role {attempt.candidate_role_id} · {attempt.verdict || "FIRST ROLE / NO MODEL"}</p><small>{attempt.used_cache ? "Cached verdict" : "Fresh path"}</small></article>) : <div className="empty-state">No assignment attempts recorded.</div>}</div></div></section>
          </> : <div className="ledger-empty"><Search /><h2>Choose a finalized workspace</h2><p>AxisLock will load its policy, role versions, assignments, and conflict decisions.</p></div>}
        </div>
      )}

      {active === "Proof" && (
        <div className="page-frame operational-page proof-page">
          <section className="module-heading"><div><span className="eyebrow">05 / DEPLOYMENT PROOF</span><h1>One source.<br />One live boundary.</h1></div><p>The interface is pinned to the accepted StudioNet deployment below. Contract identity remains RoleSeparationGuard; AxisLock is the product interface.</p></section>
          <section className="proof-grid">
            <article className="proof-primary"><FileCheck2 /><span>LIVE CONTRACT</span><h2>{CONTRACT_ADDRESS}</h2><p>Accepted on GenLayer StudioNet · chain ID 61999</p><div><Button onClick={() => void copy(CONTRACT_ADDRESS, "Contract address")}><Clipboard /> Copy address</Button><Button variant="outline" asChild><a href={EXPLORER_URL} target="_blank" rel="noreferrer">Open explorer <ExternalLink /></a></Button></div></article>
            <article><span>CONTRACT IDENTITY</span><strong>{config?.name ?? "RoleSeparationGuard"}</strong><small>v{config?.version ?? "1.1"}</small></article><article><span>DEPLOY TX</span><strong>{compact(DEPLOY_TX)}</strong><button onClick={() => void copy(DEPLOY_TX, "Deploy transaction")}>COPY</button></article><article><span>SOURCE SHA-256</span><strong>{SOURCE_SHA.slice(0, 16)}…</strong><button onClick={() => void copy(SOURCE_SHA, "Source hash")}>COPY</button></article><article><span>POLICY MUTABLE</span><strong>{config?.separation_policy_mutable ? "YES" : "NO"}</strong><small>fixed per workspace</small></article>
          </section>
          <section className="guarantee-grid"><article><Check /><h3>Immutable role versions</h3><p>Updates append a new definition; prior assignments retain their original version.</p></article><article><LockKeyhole /><h3>Permanent conflict lock</h3><p>Once validators find a role-ID pair conflicting, rewording cannot buy another evaluation.</p></article><article><ShieldCheck /><h3>Authority-scoped writes</h3><p>Only the workspace creator can evolve roles or control assignments.</p></article></section>
        </div>
      )}

      <footer className="footer"><span><LockKeyhole /> AXISLOCK / STUDIONET</span><span>Policy boundaries enforced before assignment</span><a href={EXPLORER_URL} target="_blank" rel="noreferrer">Explore contract <ExternalLink /></a></footer>
    </main>
  );
}
