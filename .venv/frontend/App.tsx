// frontend/src/App.tsx
// AdaptOS Architecture Explorer, Live Workflow Visualizer, Verification Center & Judge Demo Mode.

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  ARCHITECTURE_EDGES,
  ARCHITECTURE_NODES,
  ArchitectureComponentId,
  ArchitectureNodeSpec,
  AssetProfile,
  AuthorizedDownloadJsonResponse,
  DEFAULT_DEMO_ASSET,
  DEFAULT_DEMO_SPEC,
  DEMO_STEPS,
  DeliveryPackage,
  HealthResponse,
  ProjectRunSummary,
  Spec,
  StageNodeName,
  WORKFLOW_STAGES,
  buildGroundedHandoffFromSpec,
  parseRepairReason,
} from "./typesAndArchitectureData";

type MainWorkspaceTab = "architecture" | "workflow" | "verification" | "demo" | "chat";
type ArchSubView = "diagram" | "matrix" | "dataflow" | "security";
type VerificationLayerTab =
  | "A_dev"
  | "B_criteria"
  | "C_repair"
  | "D_eval"
  | "E_artifact";

export function App(): React.ReactElement {
  // -------------------------------------------------------------------------
  // 1. CONNECTION, SESSION AUTH & REAL BACKEND STATE
  // -------------------------------------------------------------------------
  const [apiBaseUrl, setApiBaseUrl] = useState<string>(
    () => import.meta.env.VITE_ADAPTOS_API_BASE_URL || "http://127.0.0.1:8000"
  );
  const [sessionApiKey, setSessionApiKey] = useState<string>("");
  const [showAuthModal, setShowAuthModal] = useState<boolean>(false);

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);

  // Project IDs are never hardcoded or generated in the browser;
  // they are returned by POST /api/projects or entered by the user to load an existing project.
  const [activeRunId, setActiveRunId] = useState<string>("");
  const [runInputId, setRunInputId] = useState<string>("");
  const [projectSummary, setProjectSummary] =
    useState<ProjectRunSummary | null>(null);
  const [deliveryPackage, setDeliveryPackage] =
    useState<DeliveryPackage | null>(null);
  const [ingestedProfiles, setIngestedProfiles] = useState<AssetProfile[]>([]);
  const [submittedSpecCache, setSubmittedSpecCache] = useState<Spec | null>(
    null
  );
  const [downloadedBundleJson, setDownloadedBundleJson] =
    useState<AuthorizedDownloadJsonResponse | null>(null);

  // Chat / Your Adapted AI state
  const [runtimeAppId, setRuntimeAppId] = useState<string | null>(null);
  const [runtimeAppStatus, setRuntimeAppStatus] = useState<string | null>(null);
  const [runtimeProvisionError, setRuntimeProvisionError] = useState<string | null>(null);
  const [chatSessions, setChatSessions] = useState<Array<{session_id: string; title: string}>>([]);
  const [activeChatSessionId, setActiveChatSessionId] = useState<string | null>(null);
  const [chatMessages, setChatMessages] = useState<Array<{role: string; content: string; turn_id?: string}>>([]);
  const [chatInput, setChatInput] = useState<string>("");
  const [chatLoading, setChatLoading] = useState<boolean>(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const [isProvisioning, setIsProvisioning] = useState<boolean>(false);


  const [autoPoll, setAutoPoll] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [actionBanner, setActionBanner] = useState<{
    kind: "info" | "error" | "success";
    message: string;
  } | null>(null);

  // -------------------------------------------------------------------------
  // 2. NAVIGATION & EXPLORER UI STATE
  // -------------------------------------------------------------------------
  const [activeTab, setActiveTab] = useState<MainWorkspaceTab>("architecture");
  const [archSubView, setArchSubView] = useState<ArchSubView>("diagram");
  const [selectedArchNodeId, setSelectedArchNodeId] =
    useState<ArchitectureComponentId>("adaptos_service");
  const [selectedWorkflowNode, setSelectedWorkflowNode] =
    useState<StageNodeName>("init_run");
  const [activeVerificationLayer, setActiveVerificationLayer] =
    useState<VerificationLayerTab>("D_eval");
  const [demoStepIndex, setDemoStepIndex] = useState<number>(0);

  const buildHeaders = useCallback(
    (includeJsonContentType = true): HeadersInit => {
      const headers: Record<string, string> = {};
      if (includeJsonContentType) {
        headers["Content-Type"] = "application/json";
      }
      if (sessionApiKey.trim()) {
        headers["Authorization"] = `Bearer ${sessionApiKey.trim()}`;
      }
      return headers;
    },
    [sessionApiKey]
  );

  // -------------------------------------------------------------------------
  // 3. REAL BACKEND FETCHERS (ZERO FAKE DATA)
  // -------------------------------------------------------------------------
  const checkBackendHealth = useCallback(async () => {
    try {
      const res = await fetch(`${apiBaseUrl.replace(/\/$/, "")}/health`);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const data = (await res.json()) as HealthResponse;
      setHealth(data);
      setHealthError(null);
    } catch (err) {
      setHealth(null);
      setHealthError(
        err instanceof Error ? err.message : "Backend unreachable"
      );
    }
  }, [apiBaseUrl]);

  const fetchProjectAndDelivery = useCallback(
    async (targetRunId: string, quiet = false) => {
      const cleanId = targetRunId.trim();
      if (!cleanId) {
        if (!quiet) {
          setActionBanner({
            kind: "error",
            message:
              "Enter an existing project run_id to load, or click 'INIT + APPROVE DEMO SPEC' to generate a new project.",
          });
        }
        return;
      }
      if (!quiet) setIsLoading(true);
      try {
        const base = apiBaseUrl.replace(/\/$/, "");
        const res = await fetch(
          `${base}/api/projects/${encodeURIComponent(cleanId)}`,
          { headers: buildHeaders(false) }
        );
        if (!res.ok) {
          const errBody = await res.json().catch(() => ({}));
          throw new Error(
            errBody.message ||
            `HTTP ${res.status} fetching project '${cleanId}'`
          );
        }
        const summary = (await res.json()) as ProjectRunSummary;
        setProjectSummary(summary);
        setActiveRunId(summary.run_id);
        setRunInputId(summary.run_id);

        if (summary.stage === "delivered" && summary.delivery_blob_sha256) {
          const pkgRes = await fetch(
            `${base}/api/projects/${encodeURIComponent(
              summary.run_id
            )}/delivery-package`,
            { headers: buildHeaders(false) }
          );
          if (pkgRes.ok) {
            const pkg = (await pkgRes.json()) as DeliveryPackage;
            setDeliveryPackage(pkg);
          } else {
            setDeliveryPackage(null);
          }
        } else {
          setDeliveryPackage(null);
        }

        if (!quiet) {
          setActionBanner({
            kind: "success",
            message: `Synchronized live status for project '${summary.run_id}' (stage=${summary.stage}).`,
          });
        }
      } catch (err) {
        if (!quiet) {
          setActionBanner({
            kind: "error",
            message:
              err instanceof Error
                ? err.message
                : "Failed to fetch project status.",
          });
        }
      } finally {
        if (!quiet) setIsLoading(false);
      }
    },
    [apiBaseUrl, buildHeaders]
  );

  useEffect(() => {
    void checkBackendHealth();
  }, [checkBackendHealth]);

  useEffect(() => {
    if (!autoPoll || !activeRunId) return;
    const timer = window.setInterval(() => {
      void fetchProjectAndDelivery(activeRunId, true);
    }, 2500);
    return () => window.clearInterval(timer);
  }, [autoPoll, activeRunId, fetchProjectAndDelivery]);

  // -------------------------------------------------------------------------
  // 4. INTERACTIVE API ACTIONS (Backend-Generated Unique run_id Flow)
  // -------------------------------------------------------------------------
  const handleInitializeAndApproveProject = async () => {
    setIsLoading(true);
    setActionBanner(null);
    setDownloadedBundleJson(null);
    try {
      const base = apiBaseUrl.replace(/\/$/, "");

      // Step 1: Create project WITHOUT a run_id so backend generates a unique UUID-based run_id
      const createRes = await fetch(`${base}/api/projects`, {
        method: "POST",
        headers: buildHeaders(true),
        body: JSON.stringify({
          user_goal: DEFAULT_DEMO_SPEC.goal,
          max_repair_attempts: 3,
        }),
      });
      if (!createRes.ok) {
        const err = await createRes.json().catch(() => ({}));
        throw new Error(
          err.message || `Create project failed (HTTP ${createRes.status})`
        );
      }
      const createdSummary = (await createRes.json()) as ProjectRunSummary;
      const backendRunId = createdSummary.run_id;
      if (!backendRunId) {
        throw new Error("Backend did not return a generated run_id.");
      }

      // Store backend-generated run_id in frontend state and use it for all subsequent calls
      setActiveRunId(backendRunId);
      setRunInputId(backendRunId);
      setProjectSummary(createdSummary);

      // Step 2: Upload & profile source asset using backendRunId
      const assetRes = await fetch(
        `${base}/api/projects/${encodeURIComponent(backendRunId)}/assets`,
        {
          method: "POST",
          headers: buildHeaders(true),
          body: JSON.stringify({ assets: [DEFAULT_DEMO_ASSET] }),
        }
      );
      if (!assetRes.ok) {
        const err = await assetRes.json().catch(() => ({}));
        throw new Error(
          err.message || `Asset upload failed (HTTP ${assetRes.status})`
        );
      }
      const assetData = (await assetRes.json()) as {
        profiles: AssetProfile[];
      };
      setIngestedProfiles(assetData.profiles);

      // Step 3: Submit Spec for review using backendRunId
      const specRes = await fetch(
        `${base}/api/projects/${encodeURIComponent(backendRunId)}/spec`,
        {
          method: "POST",
          headers: buildHeaders(true),
          body: JSON.stringify({ spec: DEFAULT_DEMO_SPEC }),
        }
      );
      if (!specRes.ok) {
        const err = await specRes.json().catch(() => ({}));
        throw new Error(
          err.message || `Spec submission failed (HTTP ${specRes.status})`
        );
      }
      setSubmittedSpecCache(DEFAULT_DEMO_SPEC);

      // Step 4: Construct grounded HandoffPackage and approve Spec using backendRunId
      const handoffPayload = await buildGroundedHandoffFromSpec(
        DEFAULT_DEMO_SPEC
      );
      const approveRes = await fetch(
        `${base}/api/projects/${encodeURIComponent(backendRunId)}/approve`,
        {
          method: "POST",
          headers: buildHeaders(true),
          body: JSON.stringify({ handoff: handoffPayload }),
        }
      );
      if (!approveRes.ok) {
        const err = await approveRes.json().catch(() => ({}));
        throw new Error(
          err.message || `Handoff approval failed (HTTP ${approveRes.status})`
        );
      }

      const approvedSummary = (await approveRes.json()) as ProjectRunSummary;
      setProjectSummary(approvedSummary);
      setActiveRunId(approvedSummary.run_id);
      setRunInputId(approvedSummary.run_id);
      setDeliveryPackage(null);
      setActionBanner({
        kind: "success",
        message: `Project '${approvedSummary.run_id}' created by backend, asset profiled, and HandoffPackage approved (stage=${approvedSummary.stage}).`,
      });
    } catch (err) {
      setActionBanner({
        kind: "error",
        message:
          err instanceof Error
            ? err.message
            : "Project initialization failed.",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleExecuteFullWorkflow = async () => {
    if (!activeRunId) return;
    setIsLoading(true);
    setActionBanner(null);
    try {
      const base = apiBaseUrl.replace(/\/$/, "");
      const res = await fetch(
        `${base}/api/projects/${encodeURIComponent(activeRunId)}/execute`,
        {
          method: "POST",
          headers: buildHeaders(false),
        }
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(
          err.message || `Workflow execution failed (HTTP ${res.status})`
        );
      }
      await fetchProjectAndDelivery(activeRunId, true);
      setActionBanner({
        kind: "success",
        message: `Executed factory workflow for '${activeRunId}'.`,
      });
    } catch (err) {
      setActionBanner({
        kind: "error",
        message: err instanceof Error ? err.message : "Execution failed.",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleExecuteSingleStage = async (stageName: StageNodeName) => {
    if (!activeRunId) return;
    setIsLoading(true);
    setActionBanner(null);
    try {
      const base = apiBaseUrl.replace(/\/$/, "");
      const res = await fetch(
        `${base}/api/projects/${encodeURIComponent(
          activeRunId
        )}/stages/${stageName}`,
        {
          method: "POST",
          headers: buildHeaders(false),
        }
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(
          err.message || `Stage '${stageName}' failed (HTTP ${res.status})`
        );
      }
      await fetchProjectAndDelivery(activeRunId, true);
      setActionBanner({
        kind: "success",
        message: `Executed stage '${stageName}' on project '${activeRunId}'.`,
      });
    } catch (err) {
      setActionBanner({
        kind: "error",
        message: err instanceof Error ? err.message : "Stage execution failed.",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleAuthorizedDownload = async (format: "zip" | "json") => {
    if (!activeRunId) return;
    setIsLoading(true);
    setActionBanner(null);
    try {
      const base = apiBaseUrl.replace(/\/$/, "");
      const res = await fetch(
        `${base}/api/projects/${encodeURIComponent(
          activeRunId
        )}/download?format=${format}`,
        { headers: buildHeaders(false) }
      );
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(
          `HTTP ${res.status} (${errBody.error_code || "forbidden"}): ${errBody.message || "Artifact download denied."
          }`
        );
      }
      if (format === "json") {
        const data = (await res.json()) as AuthorizedDownloadJsonResponse;
        setDownloadedBundleJson(data);
        setActionBanner({
          kind: "success",
          message: `Authorized JSON artifact bundle downloaded (${Object.keys(data.files).length
            } verified files).`,
        });
      } else {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${activeRunId}-${projectSummary?.frozen_version_id || "bundle"
          }.zip`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        setActionBanner({
          kind: "success",
          message: `Authorized ZIP bundle downloaded for '${activeRunId}'.`,
        });
      }
    } catch (err) {
      setActionBanner({
        kind: "error",
        message:
          err instanceof Error
            ? err.message
            : "Authorized download failed.",
      });
    } finally {
      setIsLoading(false);
    }
  };

  // -------------------------------------------------------------------------
  // 5. DERIVED WORKFLOW & VERIFICATION DATA FROM REAL BACKEND RESPONSES
  // -------------------------------------------------------------------------
  const selectedArchNode: ArchitectureNodeSpec = useMemo(
    () =>
      ARCHITECTURE_NODES.find((n) => n.id === selectedArchNodeId) ||
      ARCHITECTURE_NODES[0],
    [selectedArchNodeId]
  );

  const workflowNodeStates = useMemo(() => {
    const map: Record<
      StageNodeName,
      "completed" | "active" | "pending" | "failed"
    > = {
      init_run: "pending",
      design_eval: "pending",
      split_and_seal: "pending",
      build: "pending",
      dev_test: "pending",
      repair: "pending",
      freeze: "pending",
      evaluate: "pending",
      deliver: "pending",
    };
    if (!projectSummary) return map;

    const eventsJoined = projectSummary.events.join("\n");
    const hasEventPrefix = (node: StageNodeName) =>
      eventsJoined.includes(`[${node}]`);
    const hasErrorPrefix = (node: StageNodeName) =>
      eventsJoined.includes(`[${node}] ERROR`);

    for (const st of WORKFLOW_STAGES) {
      if (hasErrorPrefix(st.node)) {
        map[st.node] = "failed";
      } else if (hasEventPrefix(st.node)) {
        map[st.node] = "completed";
      }
    }

    const stage = projectSummary.stage;
    if (stage === "eval_design") {
      if (!hasEventPrefix("init_run")) map.init_run = "active";
      else if (!hasEventPrefix("design_eval")) map.design_eval = "active";
      else if (!hasEventPrefix("split_and_seal")) map.split_and_seal = "active";
      else map.build = "active";
    } else if (stage === "building") {
      map.build = "active";
    } else if (stage === "dev_testing") {
      map.dev_test = "active";
    } else if (stage === "repairing") {
      map.repair = "active";
    } else if (stage === "frozen") {
      map.evaluate = "active";
    } else if (stage === "verdict_issued") {
      map.deliver = "active";
    }
    return map;
  }, [projectSummary]);

  const activeSpec: Spec | null =
    deliveryPackage?.spec ||
    projectSummary?.verification_snapshot?.spec ||
    submittedSpecCache;

  const activeRepairLog =
    deliveryPackage?.repair_log ||
    projectSummary?.verification_snapshot?.repair_log ||
    [];

  const activeVerdict = deliveryPackage?.verdict || null;
  const activeManifest =
    deliveryPackage?.artifact ||
    projectSummary?.verification_snapshot?.candidate_manifest ||
    null;

  const applyDemoStepSelection = (stepIdx: number) => {
    const clamped = Math.max(0, Math.min(stepIdx, DEMO_STEPS.length - 1));
    setDemoStepIndex(clamped);
    const step = DEMO_STEPS[clamped];
    if (step.focusComponentId) {
      setSelectedArchNodeId(step.focusComponentId);
    }
    if (step.focusWorkflowNode) {
      setSelectedWorkflowNode(step.focusWorkflowNode);
    }
    if (step.focusVerificationLayer) {
      setActiveVerificationLayer(step.focusVerificationLayer);
    }
  };

  const currentDemoStep = DEMO_STEPS[demoStepIndex];


  // -------------------------------------------------------------------------
  // CHAT HELPERS — Your Adapted AI
  // -------------------------------------------------------------------------
  const provisionAndLoadApp = React.useCallback(async () => {
    if (!activeRunId || !sessionApiKey.trim()) return;
    setIsProvisioning(true);
    setRuntimeProvisionError(null);
    const base = apiBaseUrl.replace(/\/$/, "");
    const headers = { "Content-Type": "application/json", "Authorization": `Bearer ${sessionApiKey.trim()}` };
    try {
      const provRes = await fetch(`${base}/api/projects/${encodeURIComponent(activeRunId)}/runtime/provision`, {
        method: "POST", headers, body: JSON.stringify({ app_id: null }),
      });
      if (!provRes.ok) {
        const e = await provRes.json().catch(() => ({}));
        throw new Error(e.message || e.detail || `Provision failed (HTTP ${provRes.status})`);
      }
      const summary = await provRes.json();
      setRuntimeAppId(summary.app_id as string);
      setRuntimeAppStatus(summary.state as string);
      // Load sessions
      const sessRes = await fetch(`${base}/api/runtime/apps/${encodeURIComponent(summary.app_id)}/sessions`, { headers });
      if (sessRes.ok) {
        const sessions = await sessRes.json();
        setChatSessions(sessions as Array<{session_id: string; title: string}>);
        if ((sessions as Array<{session_id: string}>).length > 0) {
          setActiveChatSessionId((sessions as Array<{session_id: string}>)[0].session_id);
        }
      }
    } catch (err) {
      setRuntimeProvisionError(err instanceof Error ? err.message : "Provision failed");
    } finally {
      setIsProvisioning(false);
    }
  }, [activeRunId, sessionApiKey, apiBaseUrl]);

  const createNewChatSession = React.useCallback(async () => {
    if (!runtimeAppId || !sessionApiKey.trim()) return;
    const base = apiBaseUrl.replace(/\/$/, "");
    const headers = { "Content-Type": "application/json", "Authorization": `Bearer ${sessionApiKey.trim()}` };
    try {
      const res = await fetch(`${base}/api/runtime/apps/${encodeURIComponent(runtimeAppId)}/sessions`, {
        method: "POST", headers, body: JSON.stringify({ title: null }),
      });
      if (!res.ok) throw new Error(`Create session failed (HTTP ${res.status})`);
      const session = await res.json();
      setChatSessions(prev => [session as {session_id: string; title: string}, ...prev]);
      setActiveChatSessionId((session as {session_id: string}).session_id);
      setChatMessages([]);
    } catch (err) {
      setChatError(err instanceof Error ? err.message : "Failed to create session");
    }
  }, [runtimeAppId, sessionApiKey, apiBaseUrl]);

  const loadSessionMessages = React.useCallback(async (sessionId: string) => {
    if (!runtimeAppId || !sessionApiKey.trim()) return;
    const base = apiBaseUrl.replace(/\/$/, "");
    const headers = { "Authorization": `Bearer ${sessionApiKey.trim()}` };
    try {
      const res = await fetch(`${base}/api/runtime/apps/${encodeURIComponent(runtimeAppId)}/sessions/${encodeURIComponent(sessionId)}/messages`, { headers });
      if (!res.ok) return;
      const msgs = await res.json();
      setChatMessages(msgs as Array<{role: string; content: string; turn_id?: string}>);
    } catch (_) { /* silent */ }
  }, [runtimeAppId, sessionApiKey, apiBaseUrl]);

  const sendChatMessage = React.useCallback(async () => {
    if (!runtimeAppId || !activeChatSessionId || !chatInput.trim() || chatLoading) return;
    const userMsg = chatInput.trim();
    setChatInput("");
    setChatMessages(prev => [...prev, { role: "user", content: userMsg }]);
    setChatLoading(true);
    setChatError(null);
    const base = apiBaseUrl.replace(/\/$/, "");
    const headers = { "Content-Type": "application/json", "Authorization": `Bearer ${sessionApiKey.trim()}` };
    try {
      const res = await fetch(
        `${base}/api/runtime/apps/${encodeURIComponent(runtimeAppId)}/sessions/${encodeURIComponent(activeChatSessionId)}/messages`,
        { method: "POST", headers, body: JSON.stringify({ user_message: userMsg }) }
      );
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error(e.message || e.detail || `Error (HTTP ${res.status})`);
      }
      const response = await res.json();
      const assistantContent = (response as {assistant_message?: string; answer?: string; content?: string}).assistant_message
        || (response as {assistant_message?: string; answer?: string; content?: string}).answer
        || (response as {assistant_message?: string; answer?: string; content?: string}).content
        || JSON.stringify(response);
      setChatMessages(prev => [...prev, { role: "assistant", content: assistantContent as string }]);
    } catch (err) {
      setChatError(err instanceof Error ? err.message : "Failed to send message");
    } finally {
      setChatLoading(false);
    }
  }, [runtimeAppId, activeChatSessionId, chatInput, chatLoading, sessionApiKey, apiBaseUrl]);

  React.useEffect(() => {
    if (activeTab === "chat" && activeRunId && !runtimeAppId && !isProvisioning) {
      void provisionAndLoadApp();
    }
  }, [activeTab, activeRunId, runtimeAppId, isProvisioning, provisionAndLoadApp]);

  React.useEffect(() => {
    if (activeChatSessionId) void loadSessionMessages(activeChatSessionId);
  }, [activeChatSessionId, loadSessionMessages]);

  
  return (
    <div className="adaptos-shell">
      {/* ===================================================================
          TOP COMMAND BAR
      =================================================================== */}
      <header className="adaptos-topbar">
        <div className="brand-cluster">
          <div className="brand-mark">ADAPTOS</div>
          <div className="brand-divider" />
          <div className="brand-subtitle">
            EVIDENCE-BACKED AI FACTORY &amp; PROTECTED EVALUATION PLANE
          </div>
        </div>

        <nav className="workspace-tabs" aria-label="Main Workspaces">
          <button
            type="button"
            className={`ws-tab ${activeTab === "architecture" ? "active" : ""}`}
            onClick={() => setActiveTab("architecture")}
          >
            01 / ARCHITECTURE EXPLORER
          </button>
          <button
            type="button"
            className={`ws-tab ${activeTab === "workflow" ? "active" : ""}`}
            onClick={() => setActiveTab("workflow")}
          >
            02 / WORKFLOW EXECUTION
          </button>
          <button
            type="button"
            className={`ws-tab ${activeTab === "verification" ? "active" : ""}`}
            onClick={() => setActiveTab("verification")}
          >
            03 / VERIFICATION CENTER
          </button>
          <button
            type="button"
            className={`ws-tab demo-highlight ${activeTab === "demo" ? "active" : ""
              }`}
            onClick={() => setActiveTab("demo")}
          >
            04 / JUDGE DEMO MODE
          </button>
          <button
            type="button"
            className={`ws-tab chat-highlight ${activeTab === "chat" ? "active" : ""}`}
            onClick={() => setActiveTab("chat")}
          >
            05 / YOUR ADAPTED AI
          </button>
        </nav>

        <div className="status-cluster">
          <div
            className={`health-pill ${health ? "online" : "offline"}`}
            title={
              health
                ? `Service: ${health.service} v${health.version} | Sandbox Subprocess Fallback: ${health.sandbox_subprocess_fallback_enabled}`
                : healthError || "Checking /health..."
            }
          >
            <span className="dot" />
            {health ? `API ONLINE (v${health.version})` : "API OFFLINE"}
          </div>
          <button
            type="button"
            className="btn-ghost"
            onClick={() => setShowAuthModal((v) => !v)}
          >
            {sessionApiKey ? "AUTH: CONFIGURED" : "CONNECTION & AUTH"}
          </button>
        </div>
      </header>

      {/* ===================================================================
          PROJECT CONTEXT & LIVE TELEMETRY BAR
      =================================================================== */}
      <section className="project-bar">
        <div className="project-selector">
          <label htmlFor="run-id-input" className="mono-label">
            PROJECT RUN_ID
          </label>
          <input
            id="run-id-input"
            type="text"
            className="mono-input"
            value={runInputId}
            onChange={(e) => setRunInputId(e.target.value)}
            placeholder="Backend-generated or existing run_id"
          />
          <button
            type="button"
            className="btn-secondary"
            disabled={isLoading || !(runInputId.trim() || activeRunId.trim())}
            onClick={() =>
              void fetchProjectAndDelivery(runInputId.trim() || activeRunId)
            }
          >
            LOAD / REFRESH
          </button>
          <button
            type="button"
            className="btn-primary"
            disabled={isLoading}
            onClick={() => void handleInitializeAndApproveProject()}
          >
            INIT + APPROVE DEMO SPEC
          </button>
          <button
            type="button"
            className="btn-primary"
            disabled={isLoading || !activeRunId}
            onClick={() => void handleExecuteFullWorkflow()}
          >
            EXECUTE PIPELINE
          </button>
          <label className="poll-toggle">
            <input
              type="checkbox"
              checked={autoPoll}
              onChange={(e) => setAutoPoll(e.target.checked)}
            />
            <span>AUTO-POLL (2.5s)</span>
          </label>
        </div>

        <div className="project-kpis">
          <div className="kpi-chip">
            <span className="kpi-label">ACTIVE RUN_ID</span>
            <span className="kpi-val mono">
              {activeRunId || "NONE"}
            </span>
          </div>
          <div className="kpi-chip">
            <span className="kpi-label">STAGE</span>
            <span className="kpi-val mono">
              {projectSummary?.stage?.toUpperCase() || "UNLOADED"}
            </span>
          </div>
          <div className="kpi-chip">
            <span className="kpi-label">DEV SUITE (UNTRUSTED)</span>
            <span className="kpi-val mono">
              {projectSummary?.dev_pass_rate !== null &&
                projectSummary?.dev_pass_rate !== undefined
                ? `${(projectSummary.dev_pass_rate * 100).toFixed(0)}% (${projectSummary.dev_test_passed ? "PASS" : "FAIL"
                })`
                : "N/A"}
            </span>
          </div>
          <div className="kpi-chip">
            <span className="kpi-label">REPAIRS</span>
            <span className="kpi-val mono">
              {projectSummary
                ? `${projectSummary.repair_attempts} / ${projectSummary.repair_attempts +
                projectSummary.repair_budget_left
                }`
                : "0 / 3"}
            </span>
          </div>
          <div
            className={`kpi-chip verdict-chip ${projectSummary?.verdict_status === "ready"
                ? "verdict-ready"
                : projectSummary?.verdict_status
                  ? "verdict-not-ready"
                  : ""
              }`}
          >
            <span className="kpi-label">PROTECTED VERDICT</span>
            <span className="kpi-val mono">
              {projectSummary?.verdict_status
                ? projectSummary.verdict_status.toUpperCase()
                : "PENDING"}
            </span>
          </div>
          <div
            className={`kpi-chip ${projectSummary?.is_ready_for_delivery
                ? "verdict-ready"
                : "verdict-not-ready"
              }`}
          >
            <span className="kpi-label">DELIVERY GATE</span>
            <span className="kpi-val mono">
              {projectSummary?.is_ready_for_delivery
                ? "AUTHORIZED"
                : "LOCKED / DENIED"}
            </span>
          </div>
        </div>
      </section>

      {/* ===================================================================
          CONNECTION & AUTH MODAL
      =================================================================== */}
      {showAuthModal && (
        <div className="auth-drawer">
          <div className="auth-drawer-inner">
            <div>
              <div className="section-eyebrow">
                API CONNECTION &amp; EPHEMERAL SESSION CREDENTIAL
              </div>
              <p className="muted-copy">
                Per security policy, permanent secrets are never embedded in
                browser code. Configure your FastAPI base URL (or server-side
                proxy path) and optional session Bearer token below.
              </p>
            </div>
            <div className="auth-fields">
              <label>
                <span>FASTAPI BASE URL</span>
                <input
                  type="text"
                  className="mono-input"
                  value={apiBaseUrl}
                  onChange={(e) => setApiBaseUrl(e.target.value)}
                />
              </label>
              <label>
                <span>EPHEMERAL BEARER KEY (ADAPTOS_API_KEY)</span>
                <input
                  type="password"
                  className="mono-input"
                  value={sessionApiKey}
                  onChange={(e) => setSessionApiKey(e.target.value)}
                  placeholder="Session-only Bearer key (not persisted)"
                />
              </label>
              <button
                type="button"
                className="btn-primary"
                onClick={() => {
                  void checkBackendHealth();
                  setShowAuthModal(false);
                }}
              >
                APPLY &amp; PROBE /HEALTH
              </button>
            </div>
          </div>
        </div>
      )}

      {actionBanner && (
        <div className={`action-banner ${actionBanner.kind}`}>
          <span className="mono">[{actionBanner.kind.toUpperCase()}]</span>{" "}
          <span>{actionBanner.message}</span>
          <button
            type="button"
            className="banner-close"
            onClick={() => setActionBanner(null)}
          >
            ×
          </button>
        </div>
      )}

      {/* ===================================================================
          JUDGE DEMO MODE GUIDED BANNER (Persistent when in Demo Mode)
      =================================================================== */}
      {activeTab === "demo" && (
        <section className="demo-guide-panel">
          <div className="demo-step-header">
            <div>
              <span className="section-eyebrow">
                JUDGE WALKTHROUGH • STEP {currentDemoStep.stepNumber} OF{" "}
                {DEMO_STEPS.length}
              </span>
              <h2 className="demo-title">{currentDemoStep.title}</h2>
              <p className="demo-subtitle">{currentDemoStep.subtitle}</p>
            </div>
            <div className="demo-nav-buttons">
              <button
                type="button"
                className="btn-secondary"
                disabled={demoStepIndex === 0}
                onClick={() => applyDemoStepSelection(demoStepIndex - 1)}
              >
                ← PREV STEP
              </button>
              <button
                type="button"
                className="btn-primary"
                disabled={demoStepIndex === DEMO_STEPS.length - 1}
                onClick={() => applyDemoStepSelection(demoStepIndex + 1)}
              >
                NEXT STEP →
              </button>
            </div>
          </div>

          <div className="demo-step-pills">
            {DEMO_STEPS.map((st, idx) => (
              <button
                key={st.stepNumber}
                type="button"
                className={`demo-pill ${idx === demoStepIndex ? "active" : ""}`}
                onClick={() => applyDemoStepSelection(idx)}
              >
                {st.stepNumber}. {st.title.split("&")[0].trim()}
              </button>
            ))}
          </div>

          <div className="demo-narrative-grid">
            <div className="demo-card">
              <div className="mono-label">ENGINEERING NARRATIVE</div>
              <p>{currentDemoStep.narrative}</p>
            </div>
            <div className="demo-card">
              <div className="mono-label">
                VERIFIED SOURCE CODE &amp; TAKEAWAY
              </div>
              <div className="code-ref-badge mono">
                {currentDemoStep.codeEvidenceRef}
              </div>
              <p className="takeaway-text">{currentDemoStep.keyTakeaway}</p>
              <div className="demo-jump-actions">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setActiveTab(currentDemoStep.targetTab)}
                >
                  OPEN FULL {currentDemoStep.targetTab.toUpperCase()} VIEW ↗
                </button>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* ===================================================================
          WORKSPACE 1: ARCHITECTURE EXPLORER
      =================================================================== */}
      {(activeTab === "architecture" ||
        (activeTab === "demo" &&
          currentDemoStep.targetTab === "architecture")) && (
          <main className="workspace-container">
            <div className="workspace-header">
              <div>
                <div className="section-eyebrow">
                  SYSTEM ARCHITECTURE SOURCE OF TRUTH
                </div>
                <h1>AdaptOS 12-Component Architecture Explorer</h1>
              </div>
              <div className="subview-switcher">
                <button
                  type="button"
                  className={`sub-btn ${archSubView === "diagram" ? "active" : ""
                    }`}
                  onClick={() => setArchSubView("diagram")}
                >
                  HIGH-LEVEL DIAGRAM
                </button>
                <button
                  type="button"
                  className={`sub-btn ${archSubView === "matrix" ? "active" : ""
                    }`}
                  onClick={() => setArchSubView("matrix")}
                >
                  DETAILED COMPONENT MATRIX
                </button>
                <button
                  type="button"
                  className={`sub-btn ${archSubView === "dataflow" ? "active" : ""
                    }`}
                  onClick={() => setArchSubView("dataflow")}
                >
                  EXECUTION &amp; DATA-FLOW
                </button>
                <button
                  type="button"
                  className={`sub-btn ${archSubView === "security" ? "active" : ""
                    }`}
                  onClick={() => setArchSubView("security")}
                >
                  STORAGE &amp; SECURITY BOUNDARIES
                </button>
              </div>
            </div>

            {archSubView === "diagram" && (
              <div className="arch-explorer-split">
                <div className="arch-canvas-card">
                  <div className="canvas-legend">
                    <span>
                      <i className="legend-box zone-factory" /> Factory &amp;
                      Specification Plane
                    </span>
                    <span>
                      <i className="legend-box zone-eval" /> Protected Evaluation
                      Plane (Role=eval)
                    </span>
                    <span>
                      <i className="legend-box zone-store" /> Content-Addressed
                      &amp; SQLite Persistence
                    </span>
                  </div>

                  <svg
                    className="arch-svg"
                    viewBox="0 0 1160 520"
                    role="img"
                    aria-label="AdaptOS 12-Component Interactive Architecture Diagram"
                  >
                    <defs>
                      <marker
                        id="arrow-default"
                        viewBox="0 0 10 10"
                        refX="9"
                        refY="5"
                        markerWidth="6"
                        markerHeight="6"
                        orient="auto-start-reverse"
                      >
                        <path d="M 0 1 L 10 5 L 0 9 z" fill="#71717A" />
                      </marker>
                      <marker
                        id="arrow-active"
                        viewBox="0 0 10 10"
                        refX="9"
                        refY="5"
                        markerWidth="6"
                        markerHeight="6"
                        orient="auto-start-reverse"
                      >
                        <path d="M 0 1 L 10 5 L 0 9 z" fill="#FAFAFA" />
                      </marker>
                    </defs>

                    <rect
                      x="875"
                      y="195"
                      width="265"
                      height="305"
                      rx="6"
                      fill="rgba(255,255,255,0.02)"
                      stroke="#52525B"
                      strokeDasharray="5,5"
                    />
                    <text
                      x="890"
                      y="214"
                      fill="#A1A1AA"
                      fontSize="10"
                      fontFamily="monospace"
                    >
                      TRUST BOUNDARY: PROTECTED EVAL PLANE
                    </text>

                    {ARCHITECTURE_EDGES.map((edge, idx) => {
                      const src = ARCHITECTURE_NODES.find(
                        (n) => n.id === edge.from
                      )!;
                      const dst = ARCHITECTURE_NODES.find(
                        (n) => n.id === edge.to
                      )!;
                      const x1 = src.x + 110;
                      const y1 = src.y + 42;
                      const x2 = dst.x + 110;
                      const y2 = dst.y + 42;
                      const isHighlighted =
                        selectedArchNodeId === edge.from ||
                        selectedArchNodeId === edge.to;
                      return (
                        <g key={`${edge.from}-${edge.to}-${idx}`}>
                          <line
                            x1={x1}
                            y1={y1}
                            x2={x2}
                            y2={y2}
                            stroke={isHighlighted ? "#FAFAFA" : "#3F3F46"}
                            strokeWidth={isHighlighted ? 2 : 1.2}
                            strokeDasharray={
                              edge.category === "security" ? "4,3" : undefined
                            }
                            markerEnd={
                              isHighlighted
                                ? "url(#arrow-active)"
                                : "url(#arrow-default)"
                            }
                          />
                        </g>
                      );
                    })}

                    {ARCHITECTURE_NODES.map((node) => {
                      const isSelected = node.id === selectedArchNodeId;
                      const isEvalZone =
                        node.zone === "Protected Evaluation Plane";
                      return (
                        <g
                          key={node.id}
                          className="svg-node-group"
                          transform={`translate(${node.x}, ${node.y})`}
                          onClick={() => setSelectedArchNodeId(node.id)}
                        >
                          <rect
                            width="220"
                            height="86"
                            rx="4"
                            fill={isSelected ? "#FAFAFA" : "#121215"}
                            stroke={
                              isSelected
                                ? "#FAFAFA"
                                : isEvalZone
                                  ? "#A1A1AA"
                                  : "#27272A"
                            }
                            strokeWidth={isSelected ? 2 : 1.2}
                          />
                          <text
                            x="12"
                            y="22"
                            fill={isSelected ? "#09090B" : "#A1A1AA"}
                            fontSize="10"
                            fontFamily="monospace"
                            fontWeight="600"
                          >
                            {node.shortLabel}
                          </text>
                          <text
                            x="12"
                            y="42"
                            fill={isSelected ? "#09090B" : "#FAFAFA"}
                            fontSize="12"
                            fontWeight="700"
                          >
                            {node.title}
                          </text>
                          <text
                            x="12"
                            y="62"
                            fill={isSelected ? "#27272A" : "#71717A"}
                            fontSize="10"
                            fontFamily="monospace"
                          >
                            {node.sourceFiles[0]}
                          </text>
                          <text
                            x="12"
                            y="77"
                            fill={isSelected ? "#09090B" : "#A1A1AA"}
                            fontSize="9"
                            fontFamily="monospace"
                          >
                            ● {node.status}
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                </div>

                <aside className="arch-detail-panel">
                  <div className="detail-header">
                    <span className="mono-badge">
                      COMPONENT #{selectedArchNode.index} •{" "}
                      {selectedArchNode.zone}
                    </span>
                    <h2>{selectedArchNode.title}</h2>
                    <div className="status-tag mono">
                      STATUS: {selectedArchNode.status}
                    </div>
                  </div>

                  <div className="detail-section">
                    <div className="mono-label">ACTUAL SOURCE FILE(S)</div>
                    <div className="tag-list">
                      {selectedArchNode.sourceFiles.map((sf) => (
                        <span key={sf} className="code-chip mono">
                          {sf}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="detail-section">
                    <div className="mono-label">RESPONSIBILITY</div>
                    <p>{selectedArchNode.responsibility}</p>
                  </div>

                  <div className="detail-section">
                    <div className="mono-label">
                      IMPORTANT CLASSES &amp; FUNCTIONS
                    </div>
                    <ul className="mono-list">
                      {selectedArchNode.classesAndFunctions.map((fn) => (
                        <li key={fn}>{fn}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="detail-grid-2">
                    <div className="detail-section">
                      <div className="mono-label">INPUT CONTRACTS</div>
                      <ul className="compact-list">
                        {selectedArchNode.inputs.map((inp) => (
                          <li key={inp}>{inp}</li>
                        ))}
                      </ul>
                    </div>
                    <div className="detail-section">
                      <div className="mono-label">OUTPUT CONTRACTS</div>
                      <ul className="compact-list">
                        {selectedArchNode.outputs.map((out) => (
                          <li key={out}>{out}</li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  <div className="detail-section">
                    <div className="mono-label">
                      SECURITY &amp; STORAGE INVARIANT
                    </div>
                    <p className="security-callout">
                      {selectedArchNode.securityAndStorageNotes}
                    </p>
                  </div>

                  <div className="detail-section">
                    <div className="mono-label">DIRECT DEPENDENCIES</div>
                    <div className="tag-list">
                      {selectedArchNode.dependencies.length === 0 ? (
                        <span className="muted-copy">
                          Leaf Persistence Layer (No internal module dependencies)
                        </span>
                      ) : (
                        selectedArchNode.dependencies.map((depId) => {
                          const depNode = ARCHITECTURE_NODES.find(
                            (n) => n.id === depId
                          );
                          return (
                            <button
                              key={depId}
                              type="button"
                              className="dep-chip mono"
                              onClick={() => setSelectedArchNodeId(depId)}
                            >
                              → {depNode?.shortLabel || depId}
                            </button>
                          );
                        })
                      )}
                    </div>
                  </div>
                </aside>
              </div>
            )}

            {archSubView === "matrix" && (
              <div className="table-card">
                <table className="adaptos-table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>COMPONENT</th>
                      <th>SOURCE FILE</th>
                      <th>KEY CLASSES &amp; METHODS</th>
                      <th>IMPLEMENTATION STATUS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ARCHITECTURE_NODES.map((n) => (
                      <tr
                        key={n.id}
                        onClick={() => {
                          setSelectedArchNodeId(n.id);
                          setArchSubView("diagram");
                        }}
                        className="clickable-row"
                      >
                        <td className="mono">{n.index}</td>
                        <td>
                          <strong>{n.title}</strong>
                          <div className="muted-small">{n.zone}</div>
                        </td>
                        <td className="mono">{n.sourceFiles.join(", ")}</td>
                        <td className="mono">
                          {n.classesAndFunctions.slice(0, 3).join(" • ")}
                        </td>
                        <td>
                          <span className="status-pill-ok mono">{n.status}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {archSubView === "dataflow" && (
              <div className="dataflow-grid">
                {ARCHITECTURE_EDGES.map((edge, idx) => {
                  const src = ARCHITECTURE_NODES.find(
                    (n) => n.id === edge.from
                  )!;
                  const dst = ARCHITECTURE_NODES.find((n) => n.id === edge.to)!;
                  return (
                    <div key={idx} className="dataflow-card">
                      <div className="df-header mono">
                        <span>{src.shortLabel}</span>
                        <span>───►</span>
                        <span>{dst.shortLabel}</span>
                      </div>
                      <div className="df-contract">{edge.label}</div>
                      <div className="df-meta mono">
                        CHANNEL TYPE: {edge.category.toUpperCase()}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {archSubView === "security" && (
              <div className="security-zones-grid">
                <div className="sec-card">
                  <div className="section-eyebrow">
                    ZONE 1 • FACTORY &amp; BUILD PLANE (UNTRUSTED FOR VERDICT)
                  </div>
                  <h3>factory_storage/ (factory.db, blobs/, checkpoints.db)</h3>
                  <ul className="compact-list">
                    <li>
                      <strong>Modules:</strong> <code>intake.py</code>,{" "}
                      <code>eval_designer.py</code>, <code>builder.py</code>,{" "}
                      <code>runtime.py</code>, <code>repair.py</code>,{" "}
                      <code>graph.py</code>.
                    </li>
                    <li>
                      <strong>Access Scope:</strong> Can read/write candidate
                      bundles, DevCase[] subsets, and repair attempt reports.
                    </li>
                    <li>
                      <strong>Hard Prohibitions:</strong> Never receives held-out
                      cases from <code>vault.db</code>; holds only{" "}
                      <code>eval_public_key_bytes</code> (never the Ed25519
                      private signing seed).
                    </li>
                  </ul>
                </div>

                <div className="sec-card">
                  <div className="section-eyebrow">
                    ZONE 2 • PROTECTED EVALUATION PLANE (TRUSTED COORDINATOR)
                  </div>
                  <h3>eval_plane/ (vault.db, eval_ledger.db)</h3>
                  <ul className="compact-list">
                    <li>
                      <strong>Module:</strong>{" "}
                      <code>backend/eval_plane/evaluator.py</code>.
                    </li>
                    <li>
                      <strong>BootGuard:</strong> Enforces{" "}
                      <code>AGNOS_PROCESS_ROLE=eval</code> and aborts if factory
                      credentials exist in environment.
                    </li>
                    <li>
                      <strong>One-Shot Ledger &amp; Fencing:</strong> Atomically
                      reserves sealed-set evaluation budget in{" "}
                      <code>eval_ledger.db</code>; runs each held-out case in a
                      fresh <code>_FencedAttemptStorage</code> directory with a
                      single absolute <code>wall_seconds</code> deadline.
                    </li>
                  </ul>
                </div>

                <div className="sec-card">
                  <div className="section-eyebrow">
                    ZONE 3 • GENERATED-CODE SANDBOX (UNTRUSTED CODE ISOLATION)
                  </div>
                  <h3>Docker Container &amp; AST Linter (sandbox.py)</h3>
                  <ul className="compact-list">
                    <li>
                      <strong>Static Gate:</strong>{" "}
                      <code>SandboxVerifier.lint_ast_and_signature()</code>{" "}
                      verifies{" "}
                      <code>def run(input: dict, config: dict) -&gt; dict</code>{" "}
                      and blocks <code>eval</code>, <code>exec</code>,{" "}
                      <code>open</code>, <code>input()</code>, dunders, and
                      unallowlisted imports.
                    </li>
                    <li>
                      <strong>Container Flags:</strong>{" "}
                      <code>
                        docker run --rm -i --network none --read-only --tmpfs /tmp
                        --memory=&lt;mb&gt;m --cpus=0.5 --pids-limit=32 --user
                        65534:65534 python:3.11-slim python -I
                      </code>
                      .
                    </li>
                    <li>
                      <strong>Hidden Vector Confidentiality:</strong> Strips{" "}
                      <code>expected_subset</code> before stdin serialization and
                      redirects worker stdout/stderr during execution.
                    </li>
                  </ul>
                </div>
              </div>
            )}
          </main>
        )}

      {/* ===================================================================
          WORKSPACE 2: LIVE WORKFLOW EXECUTION VISUALIZATION
      =================================================================== */}
      {(activeTab === "workflow" ||
        (activeTab === "demo" && currentDemoStep.targetTab === "workflow")) && (
          <main className="workspace-container">
            <div className="workspace-header">
              <div>
                <div className="section-eyebrow">
                  LANGGRAPH STATE MACHINE • THREAD_ID ={" "}
                  {activeRunId || "UNASSIGNED"}
                </div>
                <h1>Live Factory Workflow Execution</h1>
              </div>
              <div className="stage-Note mono">
                STAGE DURATION NOTE: Per-stage wall-clock durations are not
                emitted by FactoryOrchestrator; only actual backend events and
                errors are rendered below.
              </div>
            </div>

            <div className="workflow-pipeline-track">
              {WORKFLOW_STAGES.map((st, idx) => {
                const stStatus = workflowNodeStates[st.node];
                const isSelected = selectedWorkflowNode === st.node;
                return (
                  <React.Fragment key={st.node}>
                    <div
                      className={`wf-node-card status-${stStatus} ${isSelected ? "selected" : ""
                        }`}
                      onClick={() => setSelectedWorkflowNode(st.node)}
                    >
                      <div className="wf-node-top mono">
                        <span>{st.label}</span>
                        <span className={`wf-badge ${stStatus}`}>
                          {stStatus.toUpperCase()}
                        </span>
                      </div>
                      <div className="wf-node-call mono">{st.underlyingCall}</div>
                      {st.node === "repair" && (
                        <div className="wf-loop-tag mono">
                          ⟲ Self-loop (max 3 attempts)
                        </div>
                      )}
                      <button
                        type="button"
                        className="btn-stage-run mono"
                        disabled={isLoading || !activeRunId}
                        onClick={(e) => {
                          e.stopPropagation();
                          void handleExecuteSingleStage(st.node);
                        }}
                      >
                        RUN NODE ▶
                      </button>
                    </div>
                    {idx < WORKFLOW_STAGES.length - 1 && (
                      <div className="wf-connector mono">──►</div>
                    )}
                  </React.Fragment>
                );
              })}
            </div>

            <div className="workflow-bottom-grid">
              <div className="wf-inspector-card">
                {(() => {
                  const meta = WORKFLOW_STAGES.find(
                    (w) => w.node === selectedWorkflowNode
                  )!;
                  return (
                    <>
                      <div className="section-eyebrow">
                        SELECTED ORCHESTRATOR NODE
                      </div>
                      <h2>{meta.label}</h2>
                      <div className="code-ref-badge mono">
                        {meta.orchestratorMethod}
                      </div>
                      <p>{meta.description}</p>
                      <div className="detail-section">
                        <div className="mono-label">EXACT CALL</div>
                        <div className="mono-box">{meta.underlyingCall}</div>
                      </div>
                      <div className="detail-section">
                        <div className="mono-label">CONDITIONAL ROUTING RULE</div>
                        <div className="mono-box">{meta.routingRule}</div>
                      </div>
                      <div className="detail-section">
                        <div className="mono-label">
                          RELEVANT STAGE OUTPUTS (FROM BACKEND SUMMARY)
                        </div>
                        <div className="mono-box">
                          {selectedWorkflowNode === "init_run" &&
                            `approved_spec_hash = ${projectSummary?.approved_spec_hash || "null"
                            }`}
                          {selectedWorkflowNode === "design_eval" &&
                            `plan_hash = ${projectSummary?.plan_hash || "null"}`}
                          {selectedWorkflowNode === "split_and_seal" &&
                            `sealed_set_id = ${projectSummary?.sealed_set_id || "null"
                            }`}
                          {selectedWorkflowNode === "build" &&
                            `baseline = ${projectSummary?.baseline_version_id || "null"
                            } | candidate = ${projectSummary?.candidate_version_id || "null"
                            }`}
                          {selectedWorkflowNode === "dev_test" &&
                            `dev_pass_rate = ${projectSummary?.dev_pass_rate !== null &&
                              projectSummary?.dev_pass_rate !== undefined
                              ? projectSummary.dev_pass_rate
                              : "null"
                            } | dev_test_passed = ${String(
                              projectSummary?.dev_test_passed ?? false
                            )}`}
                          {selectedWorkflowNode === "repair" &&
                            `repair_attempts = ${projectSummary?.repair_attempts ?? 0
                            } | repair_budget_left = ${projectSummary?.repair_budget_left ?? 3
                            }`}
                          {selectedWorkflowNode === "freeze" &&
                            `frozen_version_id = ${projectSummary?.frozen_version_id || "null"
                            }`}
                          {selectedWorkflowNode === "evaluate" &&
                            `verdict_id = ${projectSummary?.verdict_id || "null"
                            } | verdict_status = ${projectSummary?.verdict_status || "null"
                            }`}
                          {selectedWorkflowNode === "deliver" &&
                            `delivery_blob_sha256 = ${projectSummary?.delivery_blob_sha256 || "null"
                            } | is_ready_for_delivery = ${String(
                              projectSummary?.is_ready_for_delivery ?? false
                            )}`}
                        </div>
                      </div>
                    </>
                  );
                })()}
              </div>

              <div className="wf-logs-card">
                <div className="section-eyebrow">
                  REAL BACKEND EXECUTION EVENTS (FactoryGraphState.events)
                </div>
                {projectSummary?.events && projectSummary.events.length > 0 ? (
                  <div className="event-log-stream mono">
                    {projectSummary.events.map((ev, i) => (
                      <div
                        key={i}
                        className={`event-line ${ev.includes("ERROR") ? "event-err" : ""
                          }`}
                      >
                        <span className="event-idx">
                          {String(i + 1).padStart(2, "0")}
                        </span>
                        <span>{ev}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty-state mono">
                    No execution events loaded yet. Enter an existing run_id or
                    click &ldquo;INIT + APPROVE DEMO SPEC&rdquo; above.
                  </div>
                )}

                {projectSummary?.errors && projectSummary.errors.length > 0 && (
                  <div className="errors-block">
                    <div className="mono-label error-text">
                      STRUCTURED ERROR RECORDS (FactoryState.errors)
                    </div>
                    {projectSummary.errors.map((er, idx) => (
                      <div key={idx} className="error-item mono">
                        [{er.stage}] {er.code}: {er.message}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </main>
        )}

      {/* ===================================================================
          WORKSPACE 3: VERIFICATION CENTER (LAYERS A, B, C, D, E)
      =================================================================== */}
      {(activeTab === "verification" ||
        (activeTab === "demo" &&
          currentDemoStep.targetTab === "verification")) && (
          <main className="workspace-container">
            <div className="workspace-header">
              <div>
                <div className="section-eyebrow">
                  MULTI-LAYER VERIFICATION &amp; CRYPTOGRAPHIC AUDIT
                </div>
                <h1>AdaptOS Verification Center</h1>
              </div>
              <div className="subview-switcher">
                <button
                  type="button"
                  className={`sub-btn ${activeVerificationLayer === "A_dev" ? "active" : ""
                    }`}
                  onClick={() => setActiveVerificationLayer("A_dev")}
                >
                  A. DEVELOPMENT TESTING
                </button>
                <button
                  type="button"
                  className={`sub-btn ${activeVerificationLayer === "B_criteria" ? "active" : ""
                    }`}
                  onClick={() => setActiveVerificationLayer("B_criteria")}
                >
                  B. ACCEPTANCE CRITERIA
                </button>
                <button
                  type="button"
                  className={`sub-btn ${activeVerificationLayer === "C_repair" ? "active" : ""
                    }`}
                  onClick={() => setActiveVerificationLayer("C_repair")}
                >
                  C. REPAIR &amp; REGRESSION
                </button>
                <button
                  type="button"
                  className={`sub-btn ${activeVerificationLayer === "D_eval" ? "active" : ""
                    }`}
                  onClick={() => setActiveVerificationLayer("D_eval")}
                >
                  D. PROTECTED EVALUATION
                </button>
                <button
                  type="button"
                  className={`sub-btn ${activeVerificationLayer === "E_artifact" ? "active" : ""
                    }`}
                  onClick={() => setActiveVerificationLayer("E_artifact")}
                >
                  E. ARTIFACT &amp; DELIVERY
                </button>
              </div>
            </div>

            {/* ---------------------------------------------------------------
              LAYER A: DEVELOPMENT TESTING
          --------------------------------------------------------------- */}
            {activeVerificationLayer === "A_dev" && (
              <div className="verification-panel">
                <div className="trust-disclaimer-banner mono">
                  WARNING: Development test cases (DevRun) execute inside the
                  Factory Plane to guide Builder and Repair. Passing development
                  tests NEVER authorizes artifact delivery.
                </div>

                <div className="metrics-row-4">
                  <div className="metric-box">
                    <div className="mono-label">TEST SUITE RUNNER</div>
                    <div className="metric-val mono">runtime.DevTestRunner</div>
                  </div>
                  <div className="metric-box">
                    <div className="mono-label">EVALUATED VERSION</div>
                    <div className="metric-val mono">
                      {projectSummary?.frozen_version_id ||
                        projectSummary?.candidate_version_id ||
                        "N/A"}
                    </div>
                  </div>
                  <div className="metric-box">
                    <div className="mono-label">AGGREGATE DEV PASS RATE</div>
                    <div className="metric-val mono">
                      {projectSummary?.dev_pass_rate !== null &&
                        projectSummary?.dev_pass_rate !== undefined
                        ? `${(projectSummary.dev_pass_rate * 100).toFixed(1)}%`
                        : "N/A"}
                    </div>
                  </div>
                  <div className="metric-box">
                    <div className="mono-label">DEV SUITE STATUS</div>
                    <div className="metric-val mono">
                      {projectSummary?.dev_pass_rate !== null &&
                        projectSummary?.dev_pass_rate !== undefined
                        ? projectSummary.dev_test_passed
                          ? "PASSED (100%)"
                          : "FAILED (<100%)"
                        : "NOT EXECUTED"}
                    </div>
                  </div>
                </div>

                {projectSummary?.verification_snapshot?.dev_runs &&
                  projectSummary.verification_snapshot.dev_runs.length > 0 ? (
                  projectSummary.verification_snapshot.dev_runs.map(
                    (run, idx) => {
                      const devCasesById = new Map(
                        (
                          projectSummary.verification_snapshot?.dev_cases || []
                        ).map((dc) => [dc.case_id, dc])
                      );
                      return (
                        <div key={idx} className="table-card">
                          <div className="card-Subheader mono">
                            DEV RUN #{idx + 1} • VERSION: {run.version_id} • PASS
                            RATE: {(run.pass_rate * 100).toFixed(1)}%
                          </div>
                          <table className="adaptos-table">
                            <thead>
                              <tr>
                                <th>CASE ID</th>
                                <th>CRITERIA</th>
                                <th>EXPECTED OUTPUT</th>
                                <th>SCORE</th>
                                <th>STATUS</th>
                                <th>FAILURE DIAGNOSTIC NOTE</th>
                              </tr>
                            </thead>
                            <tbody>
                              {run.results.map((r) => {
                                const dc = devCasesById.get(r.case_id);
                                return (
                                  <tr key={r.case_id}>
                                    <td className="mono">{r.case_id}</td>
                                    <td className="mono">
                                      {dc ? dc.criterion_ids.join(", ") : "—"}
                                    </td>
                                    <td className="mono">
                                      {dc
                                        ? JSON.stringify(dc.expected_output)
                                        : "—"}
                                    </td>
                                    <td className="mono">{r.score.toFixed(2)}</td>
                                    <td className="mono">
                                      <span
                                        className={
                                          r.passed
                                            ? "status-pill-ok"
                                            : "status-pill-fail"
                                        }
                                      >
                                        {r.passed ? "PASS" : "FAIL"}
                                      </span>
                                    </td>
                                    <td className="mono">
                                      {r.failure_note || "—"}
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      );
                    }
                  )
                ) : (
                  <div className="api-gap-disclosure">
                    <div className="mono-label">
                      BACKEND DATA CONTRACT DISCLOSURE (api.py / service.py)
                    </div>
                    <p>
                      The current{" "}
                      <code>GET /api/projects/&#123;run_id&#125;</code> endpoint
                      returns <code>ProjectRunSummary</code> with aggregate{" "}
                      <code>dev_pass_rate</code> and <code>dev_test_passed</code>,
                      while storing per-case <code>FactoryState.dev_runs</code> (
                      <code>DevCaseResult[]</code>) and{" "}
                      <code>dev_cases_blob_sha256</code> inside{" "}
                      <code>service_project_runs</code> in <code>factory.db</code>
                      .
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* ---------------------------------------------------------------
              LAYER B: ACCEPTANCE CRITERIA
          --------------------------------------------------------------- */}
            {activeVerificationLayer === "B_criteria" && (
              <div className="verification-panel">
                {activeSpec ? (
                  <div className="table-card">
                    <div className="card-Subheader mono">
                      APPROVED SPECIFICATION GOAL: {activeSpec.goal}
                    </div>
                    <table className="adaptos-table">
                      <thead>
                        <tr>
                          <th>CRITERION ID</th>
                          <th>DESCRIPTION</th>
                          <th>EVALUATION METHOD</th>
                          <th>THRESHOLD</th>
                          <th>HELD-OUT RESULT (N_PASSED / N_CASES)</th>
                          <th>WILSON 95% CI [LOWER, UPPER]</th>
                          <th>CRITERION STATUS</th>
                        </tr>
                      </thead>
                      <tbody>
                        {activeSpec.acceptance_criteria.map((ac) => {
                          const cr = activeVerdict?.criteria.find(
                            (c) => c.criterion_id === ac.criterion_id
                          );
                          return (
                            <tr key={ac.criterion_id}>
                              <td className="mono">{ac.criterion_id}</td>
                              <td>{ac.description}</td>
                              <td className="mono">{ac.method}</td>
                              <td className="mono">
                                {(ac.min_pass_rate * 100).toFixed(0)}%
                              </td>
                              <td className="mono">
                                {cr
                                  ? `${cr.n_passed} / ${cr.n_cases} (${(
                                    cr.pass_rate * 100
                                  ).toFixed(1)}%)`
                                  : "Pending Protected Eval"}
                              </td>
                              <td className="mono">
                                {cr
                                  ? `[${(cr.wilson_lower * 100).toFixed(1)}%, ${(
                                    cr.wilson_upper * 100
                                  ).toFixed(1)}%]`
                                  : "—"}
                              </td>
                              <td className="mono">
                                {cr ? (
                                  <span
                                    className={
                                      cr.passed
                                        ? "status-pill-ok"
                                        : "status-pill-fail"
                                    }
                                  >
                                    {cr.status.toUpperCase()} (
                                    {cr.passed ? "PASS" : "FAIL"})
                                  </span>
                                ) : (
                                  <span className="muted-small">UNGRADED</span>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="empty-state mono">
                    No Specification loaded yet. Initialize a project or load a
                    delivered run to inspect Acceptance Criteria and Wilson 95%
                    confidence intervals.
                  </div>
                )}
              </div>
            )}

            {/* ---------------------------------------------------------------
              LAYER C: REPAIR & REGRESSION GATE
          --------------------------------------------------------------- */}
            {activeVerificationLayer === "C_repair" && (
              <div className="verification-panel">
                <div className="metrics-row-4">
                  <div className="metric-box">
                    <div className="mono-label">HARD GRAPH CAP</div>
                    <div className="metric-val mono">MAX 3 ATTEMPTS</div>
                  </div>
                  <div className="metric-box">
                    <div className="mono-label">ATTEMPTS USED</div>
                    <div className="metric-val mono">
                      {projectSummary?.repair_attempts ?? 0}
                    </div>
                  </div>
                  <div className="metric-box">
                    <div className="mono-label">BUDGET REMAINING</div>
                    <div className="metric-val mono">
                      {projectSummary?.repair_budget_left ?? 3}
                    </div>
                  </div>
                  <div className="metric-box">
                    <div className="mono-label">FINAL FROZEN VERSION</div>
                    <div className="metric-val mono">
                      {projectSummary?.frozen_version_id || "NOT FROZEN"}
                    </div>
                  </div>
                </div>

                {activeRepairLog.length > 0 ? (
                  <div className="table-card">
                    <div className="card-Subheader mono">
                      BOUNDED SELF-REPAIR &amp; REGRESSION GATE LEDGER
                      (RepairRecord[])
                    </div>
                    <table className="adaptos-table">
                      <thead>
                        <tr>
                          <th>ATTEMPT #</th>
                          <th>PARENT VERSION → CHILD VERSION</th>
                          <th>TARGET COMPONENT / STEP</th>
                          <th>REGRESSION GATE DECISION</th>
                          <th>REPORT BLOB SHA-256 &amp; COST</th>
                          <th>REGRESSION &amp; DIAGNOSTIC REASON</th>
                        </tr>
                      </thead>
                      <tbody>
                        {activeRepairLog.map((rec) => {
                          const parsed = parseRepairReason(rec.reason);
                          return (
                            <tr key={rec.attempt}>
                              <td className="mono">#{rec.attempt}</td>
                              <td className="mono">
                                {rec.parent_version_id} ──► {rec.new_version_id}
                              </td>
                              <td className="mono">{rec.target_component}</td>
                              <td className="mono">
                                <span
                                  className={
                                    rec.accepted
                                      ? "status-pill-ok"
                                      : "status-pill-fail"
                                  }
                                >
                                  {rec.accepted
                                    ? "ACCEPTED & PERSISTED"
                                    : "REJECTED (ROLLED BACK)"}
                                </span>
                              </td>
                              <td className="mono">
                                {parsed.reportSha256
                                  ? `blob:${parsed.reportSha256.slice(
                                    0,
                                    12
                                  )}… (${parsed.costTag})`
                                  : "—"}
                              </td>
                              <td className="mono">{parsed.summaryText}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="empty-state mono">
                    {projectSummary?.repair_attempts
                      ? `${projectSummary.repair_attempts} repair attempt(s) recorded. Load the DeliveryPackage (once stage == 'delivered') to inspect full RepairRecord entries.`
                      : "0 repair attempts triggered for this run."}
                  </div>
                )}
              </div>
            )}

            {/* ---------------------------------------------------------------
              LAYER D: PROTECTED EVALUATION PLANE
          --------------------------------------------------------------- */}
            {activeVerificationLayer === "D_eval" && (
              <div className="verification-panel">
                <div className="trust-disclaimer-banner mono">
                  CONFIDENTIALITY INVARIANT (C11 RedactionLayer): Sealed held-out
                  test inputs, expected outputs, and per-case outputs never leave
                  eval_plane/evaluator.py. Only the Ed25519-signed aggregate
                  Verdict and cryptographic commitments are exposed below.
                </div>

                {activeVerdict ? (
                  <div className="verdict-certificate-card">
                    <div className="cert-header">
                      <div>
                        <div className="section-eyebrow">
                          ED25519 SIGNED PROTECTED EVALUATION VERDICT
                        </div>
                        <h2>VERDICT ID: {activeVerdict.verdict_id}</h2>
                      </div>
                      <div
                        className={`verdict-giant-badge mono ${activeVerdict.status === "ready"
                            ? "verdict-ready"
                            : "verdict-not-ready"
                          }`}
                      >
                        {activeVerdict.status.toUpperCase()}
                      </div>
                    </div>

                    <div className="cert-grid mono">
                      <div>
                        <span className="mono-label">EVALUATED ARTIFACT</span>
                        <div>
                          {activeVerdict.artifact.version_id} (
                          {activeVerdict.artifact.artifact_hash.slice(0, 16)}…)
                        </div>
                      </div>
                      <div>
                        <span className="mono-label">SPECIFICATION SHA-256</span>
                        <div>{activeVerdict.spec_hash}</div>
                      </div>
                      <div>
                        <span className="mono-label">SEALED SET ID</span>
                        <div>{activeVerdict.sealed_set_id}</div>
                      </div>
                      <div>
                        <span className="mono-label">
                          SEALED COMMITMENT SHA-256
                        </span>
                        <div>{activeVerdict.sealed_commitment_hash}</div>
                      </div>
                      <div>
                        <span className="mono-label">
                          PRIVATE EVIDENCE STORE SHA-256
                        </span>
                        <div>{activeVerdict.evidence_hash}</div>
                      </div>
                      <div>
                        <span className="mono-label">
                          SIGNING KEY ID &amp; ISSUED UTC
                        </span>
                        <div>
                          {activeVerdict.signing_key_id} •{" "}
                          {activeVerdict.issued_at}
                        </div>
                      </div>
                    </div>

                    <div className="detail-section">
                      <div className="mono-label">
                        ED25519 SIGNATURE OVER Verdict.signing_payload()
                      </div>
                      <div className="signature-box mono">
                        {activeVerdict.signature}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="empty-state mono">
                    No Protected Evaluation Verdict issued yet (current stage:{" "}
                    {projectSummary?.stage || "unloaded"}). Execute the pipeline
                    to run EvaluatorCoordinator Steps S1–S12.
                  </div>
                )}
              </div>
            )}

            {/* ---------------------------------------------------------------
              LAYER E: ARTIFACT VERIFICATION & READY-GATED DELIVERY
          --------------------------------------------------------------- */}
            {activeVerificationLayer === "E_artifact" && (
              <div className="verification-panel">
                <div className="delivery-gate-card">
                  <div>
                    <div className="section-eyebrow">
                      READY-GATED DELIVERY AUTHORIZATION
                      (AdaptOSService.get_authorized_delivery)
                    </div>
                    <h2>
                      {projectSummary?.is_ready_for_delivery
                        ? "Delivery Authorized — Verdict Status is READY"
                        : "Delivery Locked — Requires Verified READY Verdict"}
                    </h2>
                    <p className="muted-copy">
                      <code>GET /api/projects/&#123;run_id&#125;/download</code>{" "}
                      verifies the Ed25519 Verdict signature, confirms{" "}
                      <code>
                        Verdict.artifact.artifact_hash ===
                        BundleManifest.artifact_hash
                      </code>
                      , and runs <code>AppRuntime.verify_bundle_integrity()</code>{" "}
                      on every file before release.
                    </p>
                  </div>
                  <div className="download-actions">
                    <button
                      type="button"
                      className="btn-primary"
                      disabled={isLoading || !activeRunId}
                      onClick={() => void handleAuthorizedDownload("zip")}
                    >
                      DOWNLOAD ZIP ARCHIVE
                    </button>
                    <button
                      type="button"
                      className="btn-secondary"
                      disabled={isLoading || !activeRunId}
                      onClick={() => void handleAuthorizedDownload("json")}
                    >
                      INSPECT VERIFIED BUNDLE FILES (JSON)
                    </button>
                  </div>
                </div>

                {ingestedProfiles.length > 0 && (
                  <div className="table-card">
                    <div className="card-Subheader mono">
                      PROFILED SOURCE ASSETS INGESTED FOR RUN ({activeRunId})
                    </div>
                    <table className="adaptos-table">
                      <thead>
                        <tr>
                          <th>ASSET ID</th>
                          <th>FILENAME</th>
                          <th>FORMAT</th>
                          <th>SIZE (BYTES)</th>
                          <th>CONTENT SHA-256 DIGEST</th>
                        </tr>
                      </thead>
                      <tbody>
                        {ingestedProfiles.map((ap) => (
                          <tr key={ap.asset_id}>
                            <td className="mono">{ap.asset_id}</td>
                            <td className="mono">{ap.filename}</td>
                            <td className="mono">{ap.format}</td>
                            <td className="mono">{ap.size_bytes} B</td>
                            <td className="mono">{ap.sha256}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {activeManifest && (
                  <div className="table-card">
                    <div className="card-Subheader mono">
                      SEALED BUNDLE MANIFEST • VERSION:{" "}
                      {activeManifest.version_id} (PARENT:{" "}
                      {activeManifest.parent_version_id || "none"}) • HASH:{" "}
                      {activeManifest.artifact_hash}
                    </div>
                    <div className="manifest-meta-bar mono">
                      <span>ARCH: {activeManifest.architecture}</span>
                      <span>MODEL: {activeManifest.runtime_model}</span>
                      <span>ENTRYPOINT: {activeManifest.entrypoint}</span>
                      <span>
                        LIMITS: {activeManifest.limits.wall_seconds}s /{" "}
                        {activeManifest.limits.memory_mb}MB
                      </span>
                      <span>
                        ALLOWED TOOLS:{" "}
                        {activeManifest.allowed_tools.length > 0
                          ? activeManifest.allowed_tools.join(", ")
                          : "none"}
                      </span>
                    </div>
                    <table className="adaptos-table">
                      <thead>
                        <tr>
                          <th>DECLARED RELATIVE PATH</th>
                          <th>SIZE (BYTES)</th>
                          <th>CONTENT SHA-256 DIGEST</th>
                          <th>INTEGRITY CHECK</th>
                        </tr>
                      </thead>
                      <tbody>
                        {activeManifest.files.map((af) => (
                          <tr key={af.path}>
                            <td className="mono">{af.path}</td>
                            <td className="mono">{af.size_bytes} B</td>
                            <td className="mono">{af.sha256}</td>
                            <td className="mono">
                              <span className="status-pill-ok">
                                SHA-256 BOUND
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {downloadedBundleJson && (
                  <div className="table-card">
                    <div className="card-Subheader mono">
                      AUTHORIZED BUNDLE FILE CONTENTS (
                      {downloadedBundleJson.version_id})
                    </div>
                    {Object.entries(downloadedBundleJson.files).map(
                      ([path, content]) => (
                        <div key={path} className="file-preview-block">
                          <div className="mono-label">{path}</div>
                          <pre className="code-pre mono">{content}</pre>
                        </div>
                      )
                    )}
                  </div>
                )}
              </div>
            )}
          </main>
        )}
    </div>
  );
}

export default App;
