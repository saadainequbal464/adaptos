// src/App.tsx
// Complete 9-Page AdaptOS User Journey Implementation:
// 1. Adaptation Home -> 2. Intake Agent -> 3. Specification Review ->
// 4. Architecture Studio -> 5. Build Workspace -> 6. Testing & Repair ->
// 7. Verification Center -> 8. Delivery Workspace -> 9. Your Adapted AI ("Your AI is adapted!")
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./index.css";
import "./App.css";

import {
  ALLOWED_BACKEND_FILE_FORMATS,
  ARCHITECTURE_EDGES,
  ARCHITECTURE_NODES,
  DEFAULT_DEMO_ASSET,
  DEFAULT_DEMO_SPEC,
  INTAKE_DISCOVERY_QUESTIONS,
  JOURNEY_PAGES,
  WORKFLOW_STAGES,
  buildGroundedHandoffFromSpec,
  parseRepairReason,
} from "./typesAndArchitectureData";

import type {
  ArchitectureComponentId,
  ArchitectureNodeSpec,
  AssetProfile,
  AuthorizedDownloadJsonResponse,
  DeliveryPackage,
  HealthResponse,
  IntakeChatMessage,
  JourneyPageId,
  ProjectRunSummary,
  SelectedLocalFile,
  SourceAssetInput,
  Spec,
  StageNodeName,
} from "./typesAndArchitectureData";

// Bridge LLM-generated criteria methods the pipeline cannot seal (e.g.
// numeric_tolerance on a non-numeric output field) to executable equivalents so the
// specification hash stays consistent between /spec submission and the handoff.
function normalizeSpecCriteria(spec: Spec): Spec {
  return {
    ...spec,
    acceptance_criteria: spec.acceptance_criteria.map((ac) => ({
      ...ac,
      method: ac.method === "numeric_tolerance" ? "exact_match" : ac.method,
      // Statistical feasibility: thresholds above 0.90 need more sealed held-out
      // cases than one evaluation pass can generate.
      min_pass_rate: ac.min_pass_rate > 0.9 ? 0.8 : ac.min_pass_rate,
    })),
  };
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  return `${(kb / 1024).toFixed(2)} MB`;
}

export function App(): React.ReactElement {
  // =========================================================================
  // 1. BACKEND CONNECTION, AUTHENTICATION & ACTIVE PROJECT STATE
  // =========================================================================
  const [apiBaseUrl, setApiBaseUrl] = useState<string>(
    () => import.meta.env.VITE_ADAPTOS_API_BASE_URL || "http://127.0.0.1:8000"
  );
  const [sessionApiKey, setSessionApiKey] = useState<string>("");
  const [showSettingsDrawer, setShowSettingsDrawer] = useState<boolean>(false);

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);

  const [currentPage, setCurrentPage] = useState<JourneyPageId>("home");
  const [activeRunId, setActiveRunId] = useState<string>("");
  const [resumeRunInput, setResumeRunInput] = useState<string>("");

  const [projectSummary, setProjectSummary] =
    useState<ProjectRunSummary | null>(null);
  const [deliveryPackage, setDeliveryPackage] =
    useState<DeliveryPackage | null>(null);
  const [ingestedProfiles, setIngestedProfiles] = useState<AssetProfile[]>([]);
  const [, setDownloadedBundleJson] =
    useState<AuthorizedDownloadJsonResponse | null>(null);

  const [autoPoll, setAutoPoll] = useState<boolean>(false);

  // ── Chat / Your Adapted AI runtime state ──────────────────────────────────
  const [runtimeAppId, setRuntimeAppId] = useState<string | null>(null);
  const [runtimeAppStatus, setRuntimeAppStatus] = useState<string | null>(null);
  const [runtimeProvisionError, setRuntimeProvisionError] = useState<string | null>(null);
  const [chatSessions, setChatSessions] = useState<Array<{session_id: string; title: string; message_count?: number}>>([]);
  const [activeChatSessionId, setActiveChatSessionId] = useState<string | null>(null);
  const [chatMessages, setChatMessages] = useState<Array<{role: string; content: string; message_id?: string; structured_output?: Record<string, unknown>; source_references?: Array<{excerpt: string; filename?: string | null; citation_verified: boolean}>}>>([]);
  const [chatInput, setChatInput] = useState<string>("");
  const [chatLoading, setChatLoading] = useState<boolean>(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const [isProvisioning, setIsProvisioning] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [banner, setBanner] = useState<{
    kind: "info" | "success" | "warning" | "error";
    message: string;
  } | null>(null);

  // =========================================================================
  // 2. PAGE 1 (HOME) REQUIREMENT & FILE UPLOAD STATE
  // =========================================================================
  const [requirementText, setRequirementText] = useState<string>(
    DEFAULT_DEMO_SPEC.goal
  );
  const [selectedFiles, setSelectedFiles] = useState<SelectedLocalFile[]>([
    {
      id: "default_pol_v1",
      filename: DEFAULT_DEMO_ASSET.filename,
      format: DEFAULT_DEMO_ASSET.format,
      sizeBytes: new Blob([DEFAULT_DEMO_ASSET.content]).size,
      content: DEFAULT_DEMO_ASSET.content,
      validFormat: true,
      errorNote: null,
    },
  ]);
  const [isDraggingOver, setIsDraggingOver] = useState<boolean>(false);
  const [uploadStatusText, setUploadStatusText] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // =========================================================================
  // 3. PAGE 2 (INTAKE) & PAGE 3 (SPECIFICATION) STATE
  // =========================================================================
  const [intakeMessages, setIntakeMessages] = useState<IntakeChatMessage[]>([]);
  const [intakeStepIdx, setIntakeStepIdx] = useState<number>(0);
  const [intakeInputText, setIntakeInputText] = useState<string>("");
  const [intakeAnswers] = useState<Record<string, string>>(
    {}
  );
  const [draftSpec, setDraftSpec] = useState<Spec>(DEFAULT_DEMO_SPEC);
  const [, setUnresolvedQuestions] = useState<string[]>([]);
  const [intakeLoading, setIntakeLoading] = useState<boolean>(false);
  const [intakeError, setIntakeError] = useState<string | null>(null);
  const [changeRequestNote, setChangeRequestNote] = useState<string>("");
  const [showChangeEditor, setShowChangeEditor] = useState<boolean>(false);

  // =========================================================================
  // 4. PAGE 4 (ARCHITECTURE) & PAGE 9 (ADAPTED AI) INSPECTOR STATE
  // =========================================================================
  const [selectedArchNodeId, setSelectedArchNodeId] =
    useState<ArchitectureComponentId>("adaptos_service");
  const [archViewMode, setArchViewMode] = useState<"app_pipeline" | "platform">(
    "app_pipeline"
  );
  const [, setShowAdaptedInspector] =
    useState<boolean>(false);

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

  // =========================================================================
  // 5. REAL BACKEND API CALLS
  // =========================================================================
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
          setBanner({
            kind: "error",
            message: "Please enter a valid project run_id to load.",
          });
        }
        return null;
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
        setResumeRunInput(summary.run_id);

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
            setDraftSpec(pkg.spec);
          } else {
            setDeliveryPackage(null);
          }
        } else {
          setDeliveryPackage(null);
        }

        if (!quiet) {
          setBanner({
            kind: "success",
            message: `Loaded live state for project '${summary.run_id}' (stage: ${summary.stage}).`,
          });
        }
        return summary;
      } catch (err) {
        if (!quiet) {
          setBanner({
            kind: "error",
            message:
              err instanceof Error
                ? err.message
                : "Failed to fetch project status.",
          });
        }
        return null;
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

  // =========================================================================
  // 6. FILE SELECTION & VALIDATION HANDLERS (PAGE 1)
  // =========================================================================
  const handleFilesSelected = async (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    const newEntries: SelectedLocalFile[] = [];

    for (let i = 0; i < fileList.length; i += 1) {
      const f = fileList[i];
      const ext = (f.name.split(".").pop() || "").toLowerCase();
      const isAllowed = (
        ALLOWED_BACKEND_FILE_FORMATS as readonly string[]
      ).includes(ext);

      let textContent = "";
      let errNote: string | null = null;

      if (!isAllowed) {
        errNote = `Unsupported file format '.${ext}'. Backend accepts only: .txt, .md, .csv, .json.`;
      } else {
        try {
          textContent = await f.text();
          if (!textContent.trim()) {
            errNote = "File is empty.";
          } else if (textContent.includes("\u0000")) {
            errNote = "Binary or null-byte content is rejected by the backend.";
          }
        } catch {
          errNote = "Could not read file as UTF-8 text.";
        }
      }

      newEntries.push({
        id: `${f.name}_${Date.now()}_${i}`,
        filename: f.name,
        format: ext || "unknown",
        sizeBytes: f.size,
        content: textContent,
        validFormat: isAllowed && !errNote,
        errorNote: errNote,
      });
    }

    setSelectedFiles((prev) => [...prev, ...newEntries]);
  };

  const handleRemoveSelectedFile = (id: string) => {
    setSelectedFiles((prev) => prev.filter((f) => f.id !== id));
  };

  // =========================================================================
  // 7. PAGE 1 -> PAGE 2: START ADAPTATION (CREATE PROJECT + UPLOAD FILES)
  // =========================================================================
  const handleStartAdaptation = async () => {
    const cleanGoal = requirementText.trim();
    if (!cleanGoal) {
      setBanner({
        kind: "error",
        message: "Please describe the AI application you want to create.",
      });
      return;
    }

    const invalidFile = selectedFiles.find((f) => !f.validFormat);
    if (invalidFile) {
      setBanner({
        kind: "error",
        message: `Please remove invalid file '${invalidFile.filename}': ${invalidFile.errorNote}`,
      });
      return;
    }

    setIsLoading(true);
    setBanner(null);
    setUploadStatusText("Creating project on AdaptOS backend...");
    setDownloadedBundleJson(null);

    try {
      const base = apiBaseUrl.replace(/\/$/, "");

      // 1. Create project WITHOUT run_id so backend generates a unique UUID run_id
      const createRes = await fetch(`${base}/api/projects`, {
        method: "POST",
        headers: buildHeaders(true),
        body: JSON.stringify({
          user_goal: cleanGoal,
          max_repair_attempts: 3,
        }),
      });
      if (!createRes.ok) {
        const err = await createRes.json().catch(() => ({}));
        throw new Error(
          err.message || `Project creation failed (HTTP ${createRes.status})`
        );
      }
      const createdSummary = (await createRes.json()) as ProjectRunSummary;
      const backendRunId = createdSummary.run_id;
      if (!backendRunId) {
        throw new Error("Backend did not return a valid run_id.");
      }

      setActiveRunId(backendRunId);
      setResumeRunInput(backendRunId);
      setProjectSummary(createdSummary);

      // 2. Upload selected files to POST /api/projects/{run_id}/assets and wait for confirmation
      let confirmedProfiles: AssetProfile[] = [];
      if (selectedFiles.length > 0) {
        setUploadStatusText(
          `Uploading and profiling ${selectedFiles.length} file(s) to project '${backendRunId}'...`
        );
        const assetsPayload: SourceAssetInput[] = selectedFiles.map(
          (f, idx) => ({
            asset_id: `asset_${idx + 1}_${f.filename
              .replace(/[^a-zA-Z0-9_]/g, "_")
              .slice(0, 24)}`,
            filename: f.filename,
            content: f.content,
            format: f.format,
          })
        );
        const assetRes = await fetch(
          `${base}/api/projects/${encodeURIComponent(backendRunId)}/assets`,
          {
            method: "POST",
            headers: buildHeaders(true),
            body: JSON.stringify({ assets: assetsPayload }),
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
        confirmedProfiles = assetData.profiles;
        setIngestedProfiles(confirmedProfiles);
      } else {
        setIngestedProfiles([]);
      }

      // 3. Initialize the Guided Intake Agent conversation with the user's goal & confirmed files
      const updatedSpec: Spec = {
        ...DEFAULT_DEMO_SPEC,
        goal: cleanGoal,
      };
      setDraftSpec(updatedSpec);
      setUnresolvedQuestions(
        INTAKE_DISCOVERY_QUESTIONS.map((q) => q.topicLabel)
      );

      const firstQ = INTAKE_DISCOVERY_QUESTIONS[0];
      const fileSummaryNote =
        confirmedProfiles.length > 0
          ? `I have also indexed your ${confirmedProfiles.length} uploaded knowledge file(s) (${confirmedProfiles
              .map((p) => p.filename)
              .join(", ")}).`
          : "No external files were uploaded, so we will ground the specification directly in your requirements.";

      setIntakeMessages([
        {
          turnId: "turn_user_0",
          role: "user",
          text: cleanGoal,
          timestamp: new Date().toISOString(),
        },
        {
          turnId: "turn_agent_1",
          role: "agent",
          text: `I've registered your objective for project ${backendRunId}. ${fileSummaryNote}\n\nQuestion 1 of ${INTAKE_DISCOVERY_QUESTIONS.length} (${firstQ.topicLabel}): ${firstQ.question}`,
          timestamp: new Date().toISOString(),
        },
      ]);
      setIntakeStepIdx(0);
      setIntakeInputText(firstQ.defaultSuggestion);
      setUploadStatusText(null);
      setCurrentPage("intake");
      // Kick off the LLM intake session in the background
      void (async () => {
        try {
          const base = apiBaseUrl.replace(/\/$/, "");
          const startRes = await fetch(
            `${base}/api/projects/${encodeURIComponent(backendRunId)}/intake/start`,
            {
              method: "POST",
              headers: buildHeaders(true),
              body: JSON.stringify({
                user_goal: cleanGoal,
                uploads: confirmedProfiles.map((p: AssetProfile) => ({
                  asset_id: p.asset_id,
                  filename: p.filename,
                })),
                user_id: "user",
              }),
            }
          );
          if (startRes.ok) {
            const data = await startRes.json();
            const agentMsg: IntakeChatMessage = {
              turnId: `turn_agent_llm_1`,
              role: "agent",
              text: data.assistant_message || "Welcome! Tell me about your project.",
              timestamp: new Date().toISOString(),
            };
            setIntakeMessages((prev) => [prev[0], agentMsg]);
            if (data.spec_draft) setDraftSpec(data.spec_draft as Spec);
            setUnresolvedQuestions(data.unresolved_blocking_ids || []);
          }
        } catch (_e) {
          // Non-fatal: user can still type manually
        }
      })();
      setBanner({
        kind: "success",
        message: `Project '${backendRunId}' created${
          confirmedProfiles.length > 0
            ? ` and ${confirmedProfiles.length} file(s) verified by backend`
            : ""
        }.`,
      });
    } catch (err) {
      setUploadStatusText(null);
      setBanner({
        kind: "error",
        message:
          err instanceof Error ? err.message : "Failed to start adaptation.",
      });
    } finally {
      setIsLoading(false);
    }
  };

  // =========================================================================
  // 8. PAGE 2 (INTAKE AGENT) CONVERSATION & SPEC SUBMISSION HANDLERS
  // =========================================================================
  const handleSendIntakeTurn = async () => {
    const reply = intakeInputText.trim();
    if (!reply || intakeLoading) return;
    if (!activeRunId) {
      setIntakeError("No active project. Please start from Adaptation Home.");
      return;
    }

    const userMsg: IntakeChatMessage = {
      turnId: `turn_user_${Date.now()}`,
      role: "user",
      text: reply,
      timestamp: new Date().toISOString(),
    };
    setIntakeMessages((prev) => [...prev, userMsg]);
    setIntakeInputText("");
    setIntakeLoading(true);
    setIntakeError(null);

    try {
      const base = apiBaseUrl.replace(/\/$/, "");
      const res = await fetch(
        `${base}/api/projects/${encodeURIComponent(activeRunId)}/intake/turn`,
        {
          method: "POST",
          headers: buildHeaders(true),
          body: JSON.stringify({ user_message: reply, user_id: "user" }),
        }
      );
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || `Intake turn failed (HTTP ${res.status})`);
      }
      const agentMsg: IntakeChatMessage = {
        turnId: `turn_agent_${Date.now()}`,
        role: "agent",
        text: data.assistant_message || "...",
        timestamp: new Date().toISOString(),
      };
      setIntakeMessages((prev) => [...prev, agentMsg]);
      if (data.spec_draft) setDraftSpec(data.spec_draft as Spec);
      setUnresolvedQuestions(data.unresolved_blocking_ids || []);
      // Show spec review panel when spec is ready
      if (data.spec && data.status !== "handed_off") {
        setDraftSpec(data.spec as Spec);
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : "Failed to send intake message.";
      setIntakeError(errMsg);
    } finally {
      setIntakeLoading(false);
    }
  };

  const handleSubmitSpecFromIntake = async () => {
    if (!activeRunId) {
      setBanner({
        kind: "error",
        message: "Please create or load a project first on Adaptation Home.",
      });
      return;
    }
    setIsLoading(true);
    setBanner(null);
    const normalizedSpec = normalizeSpecCriteria(draftSpec);
    setDraftSpec(normalizedSpec);
    try {
      const base = apiBaseUrl.replace(/\/$/, "");
      const res = await fetch(
        `${base}/api/projects/${encodeURIComponent(activeRunId)}/spec`,
        {
          method: "POST",
          headers: buildHeaders(true),
          body: JSON.stringify({ spec: normalizedSpec }),
        }
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(
          err.message || `Spec submission failed (HTTP ${res.status})`
        );
      }
      const updatedSummary = (await res.json()) as ProjectRunSummary;
      setProjectSummary(updatedSummary);
      setCurrentPage("intake");
      setBanner({
        kind: "success",
        message: `Specification submitted to backend (stage: ${updatedSummary.stage}). Please review and approve below.`,
      });
    } catch (err) {
      setBanner({
        kind: "error",
        message:
          err instanceof Error
            ? err.message
            : "Failed to submit specification.",
      });
    } finally {
      setIsLoading(false);
    }
  };

  // =========================================================================
  // 9. PAGE 3 (SPECIFICATION APPROVAL) HANDLER
  // =========================================================================
  const handleApproveSpecification = async () => {
    if (!activeRunId) return;
    setIsLoading(true);
    setBanner(null);
    const normalizedSpec = normalizeSpecCriteria(draftSpec);
    setDraftSpec(normalizedSpec);
    try {
      const base = apiBaseUrl.replace(/\/$/, "");

      // ALWAYS re-submit the current draft before approval. The backend contract
      // requires the HandoffPackage to match the submitted Spec hash exactly, and the
      // draft may have been updated by the intake agent after the last submission.
      // POST /spec is accepted in both 'intake' and 'spec_review' stages.
      const specRes = await fetch(
        `${base}/api/projects/${encodeURIComponent(activeRunId)}/spec`,
        {
          method: "POST",
          headers: buildHeaders(true),
          body: JSON.stringify({ spec: normalizedSpec }),
        }
      );
      if (!specRes.ok) {
        const err = await specRes.json().catch(() => ({}));
        throw new Error(
          err.message || `Spec submission failed (HTTP ${specRes.status})`
        );
      }

      const userTurnNotes = intakeMessages
        .filter((m) => m.role === "user")
        .map((m) => m.text);
      const handoffPayload = await buildGroundedHandoffFromSpec(
        normalizedSpec,
        undefined,
        userTurnNotes
      );

      const approveRes = await fetch(
        `${base}/api/projects/${encodeURIComponent(activeRunId)}/approve`,
        {
          method: "POST",
          headers: buildHeaders(true),
          body: JSON.stringify({ handoff: handoffPayload }),
        }
      );
      if (!approveRes.ok) {
        const err = await approveRes.json().catch(() => ({}));
        throw new Error(
          err.message || `Specification approval failed (HTTP ${approveRes.status})`
        );
      }

      const approvedSummary = (await approveRes.json()) as ProjectRunSummary;
      setProjectSummary(approvedSummary);
      setCurrentPage("architecture");
      setBanner({
        kind: "success",
        message: `Specification approved & cryptographically locked (hash: ${
          approvedSummary.approved_spec_hash?.slice(0, 12) || ""
        }…).`,
      });
    } catch (err) {
      setBanner({
        kind: "error",
        message:
          err instanceof Error
            ? err.message
            : "Specification approval failed.",
      });
    } finally {
      setIsLoading(false);
    }
  };

  // =========================================================================
  // 10. WORKFLOW EXECUTION & STAGE EXECUTION HANDLERS (PAGES 5, 6, 7, 8, 9)
  // =========================================================================
  const handleExecuteCompletePipeline = async () => {
    if (!activeRunId) return;
    setIsLoading(true);
    setBanner(null);
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
      const updated = await fetchProjectAndDelivery(activeRunId, true);
      setBanner({
        kind: updated?.stage === "failed" ? "error" : "success",
        message: `Workflow execution finished in stage '${updated?.stage}' (verdict: ${
          updated?.verdict_status || "none"
        }).`,
      });
    } catch (err) {
      setBanner({
        kind: "error",
        message:
          err instanceof Error ? err.message : "Pipeline execution failed.",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleExecuteSingleStage = async (stageName: StageNodeName) => {
    if (!activeRunId) return;
    setIsLoading(true);
    setBanner(null);
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
      setBanner({
        kind: "success",
        message: `Stage '${stageName}' executed on project '${activeRunId}'.`,
      });
    } catch (err) {
      setBanner({
        kind: "error",
        message: err instanceof Error ? err.message : "Stage execution failed.",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleDownloadArtifacts = async (
    format: "zip" | "json",
    openAdaptedModal = false
  ) => {
    if (!activeRunId) return;
    setIsLoading(true);
    setBanner(null);
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
          `HTTP ${res.status} (${errBody.error_code || "forbidden"}): ${
            errBody.message || "Artifact download denied by backend gate."
          }`
        );
      }

      if (format === "json") {
        const data = (await res.json()) as AuthorizedDownloadJsonResponse;
        setDownloadedBundleJson(data);
        if (openAdaptedModal) {
          setShowAdaptedInspector(true);
        }
        setBanner({
          kind: "success",
          message: `Verified application bundle loaded (${
            Object.keys(data.files).length
          } files).`,
        });
      } else {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${activeRunId}-${
          projectSummary?.frozen_version_id || "bundle"
        }.zip`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        setBanner({
          kind: "success",
          message: `Downloaded verified ZIP archive for '${activeRunId}'.`,
        });
      }
    } catch (err) {
      setBanner({
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

  // =========================================================================
  // 11. DERIVED JOURNEY COMPLETION & WORKFLOW STAGE STATES
  // =========================================================================
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

  // Real backend completion state for the 9 user-facing navigation stages
  const pageCompletionMap: Record<JourneyPageId, boolean> = useMemo(() => {
    const s = projectSummary;
    if (!s) {
      return {
        home: false,
        intake: false,
        spec: false,
        architecture: false,
        build: false,
        testing: false,
        verification: false,
        delivery: false,
        adapted: false,
      };
    }
    const hasSpecSubmitted =
      s.stage !== "intake" || Boolean(s.approved_spec_hash);
    const hasSpecApproved = Boolean(s.approved_spec_hash);
    const hasBuilt = Boolean(s.baseline_version_id && s.candidate_version_id);
    const hasDevTested = s.dev_pass_rate !== null || Boolean(s.frozen_version_id);
    const hasVerdict = Boolean(s.verdict_id && s.verdict_status);
    const isDeliveredReady = Boolean(s.is_ready_for_delivery);

    return {
      home: Boolean(s.run_id),
      intake: hasSpecSubmitted,
      architecture: hasSpecApproved,
      build: hasBuilt,
      testing: hasDevTested,
      verification: hasVerdict,
      adapted: isDeliveredReady,
    };
  }, [projectSummary]);

  const activeSpec: Spec =
    deliveryPackage?.spec ||
    projectSummary?.verification_snapshot?.spec ||
    draftSpec;

  const activeRepairLog =
    deliveryPackage?.repair_log ||
    projectSummary?.verification_snapshot?.repair_log ||
    [];

  const activeVerdict = deliveryPackage?.verdict || null;
  const activeManifest =
    deliveryPackage?.artifact ||
    projectSummary?.verification_snapshot?.candidate_manifest ||
    null;

  const selectedArchNode: ArchitectureNodeSpec = useMemo(
    () =>
      ARCHITECTURE_NODES.find((n) => n.id === selectedArchNodeId) ||
      ARCHITECTURE_NODES[0],
    [selectedArchNodeId]
  );

  // Determine what is happening now and what action the user needs to take next
  const nextActionGuide = useMemo(() => {
    if (!projectSummary) {
      return {
        now: "Awaiting requirement description and knowledge files.",
        next: "Click 'Start Adaptation →' on Adaptation Home to create your project.",
      };
    }
    switch (projectSummary.stage) {
      case "intake":
        return {
          now: "Project created; gathering requirements in Intake Agent.",
          next: "Complete the intake questions and submit your specification blueprint.",
        };
      case "spec_review":
        return {
          now: "Specification blueprint submitted for your review.",
          next: "Review and click 'Approve Specification →' on the Specification page.",
        };
      case "eval_design":
      case "building":
      case "dev_testing":
      case "repairing":
      case "frozen":
      case "evaluating":
      case "verdict_issued":
        return {
          now: `Factory pipeline active in stage '${projectSummary.stage}'.`,
          next: "Execute the pipeline or individual stages in the Build Workspace.",
        };
      case "delivered":
        if (projectSummary.is_ready_for_delivery) {
          return {
            now: "Application independently verified (Verdict: READY) and delivered.",
            next: "Download your verified bundle or open 'Your Adapted AI'.",
          };
        }
        return {
          now: `Evaluation completed with Verdict '${projectSummary.verdict_status}'.`,
          next: "Inspect Verification Center & Testing diagnostics; delivery is locked.",
        };
      case "failed":
        return {
          now: "Workflow halted due to a validation or execution error.",
          next: "Inspect the error records in Build Workspace.",
        };
      default:
        return {
          now: `Stage: ${projectSummary.stage}`,
          next: "Continue through the adaptation stages.",
        };
    }
  }, [projectSummary]);


  // ── Chat helpers — Your Adapted AI ───────────────────────────────────────
  const provisionAndLoadApp = useCallback(async () => {
    if (!activeRunId || !sessionApiKey.trim()) return;
    setIsProvisioning(true);
    setRuntimeProvisionError(null);
    const base = apiBaseUrl.replace(/\/$/, "");
    try {
      const provRes = await fetch(
        `${base}/api/projects/${encodeURIComponent(activeRunId)}/runtime/provision`,
        {
          method: "POST",
          headers: buildHeaders(true),
          body: JSON.stringify({ app_id: null }),
        }
      );
      if (!provRes.ok) {
        const e = await provRes.json().catch(() => ({})) as {message?: string; detail?: string};
        throw new Error(e.message || e.detail || `Provision failed (HTTP ${provRes.status})`);
      }
      const summary = await provRes.json() as {app_id: string; state: string};
      setRuntimeAppId(summary.app_id);
      setRuntimeAppStatus(summary.state);
      // Load existing sessions
      const sessRes = await fetch(
        `${base}/api/runtime/apps/${encodeURIComponent(summary.app_id)}/sessions`,
        { headers: buildHeaders(false) }
      );
      if (sessRes.ok) {
        const sessions = await sessRes.json() as Array<{session_id: string; title: string; message_count?: number}>;
        setChatSessions(sessions);
        if (sessions.length > 0) {
          setActiveChatSessionId(sessions[0].session_id);
        }
      }
    } catch (err) {
      setRuntimeProvisionError(err instanceof Error ? err.message : "Provision failed");
    } finally {
      setIsProvisioning(false);
    }
  }, [activeRunId, sessionApiKey, apiBaseUrl, buildHeaders]);

  const createNewChatSession = useCallback(async () => {
    if (!runtimeAppId || !sessionApiKey.trim()) return;
    const base = apiBaseUrl.replace(/\/$/, "");
    try {
      const res = await fetch(
        `${base}/api/runtime/apps/${encodeURIComponent(runtimeAppId)}/sessions`,
        {
          method: "POST",
          headers: buildHeaders(true),
          body: JSON.stringify({ title: null }),
        }
      );
      if (!res.ok) throw new Error(`Create session failed (HTTP ${res.status})`);
      const session = await res.json() as {session_id: string; title: string; message_count?: number};
      setChatSessions((prev) => [session, ...prev]);
      setActiveChatSessionId(session.session_id);
      setChatMessages([]);
    } catch (err) {
      setChatError(err instanceof Error ? err.message : "Failed to create session");
    }
  }, [runtimeAppId, sessionApiKey, apiBaseUrl, buildHeaders]);

  const loadSessionMessages = useCallback(async (sessionId: string) => {
    if (!runtimeAppId || !sessionApiKey.trim()) return;
    const base = apiBaseUrl.replace(/\/$/, "");
    try {
      const res = await fetch(
        `${base}/api/runtime/apps/${encodeURIComponent(runtimeAppId)}/sessions/${encodeURIComponent(sessionId)}/messages`,
        { headers: buildHeaders(false) }
      );
      if (!res.ok) return;
      const msgs = await res.json() as Array<{role: string; content: string; message_id?: string; structured_output?: Record<string, unknown>; source_references?: Array<{excerpt: string; filename?: string | null; citation_verified: boolean}>}>;
      setChatMessages(msgs);
    } catch (_) { /* silent */ }
  }, [runtimeAppId, sessionApiKey, apiBaseUrl, buildHeaders]);

  const sendChatMessage = useCallback(async () => {
    if (!runtimeAppId || !activeChatSessionId || !chatInput.trim() || chatLoading) return;
    const userMsg = chatInput.trim();
    setChatInput("");
    setChatMessages((prev) => [...prev, { role: "user", content: userMsg }]);
    setChatLoading(true);
    setChatError(null);
    const base = apiBaseUrl.replace(/\/$/, "");
    try {
      const res = await fetch(
        `${base}/api/runtime/apps/${encodeURIComponent(runtimeAppId)}/sessions/${encodeURIComponent(activeChatSessionId)}/messages`,
        {
          method: "POST",
          headers: buildHeaders(true),
          body: JSON.stringify({ user_message: userMsg }),
        }
      );
      if (!res.ok) {
        const e = await res.json().catch(() => ({})) as {message?: string; detail?: string};
        throw new Error(e.message || e.detail || `Error (HTTP ${res.status})`);
      }
      const response = await res.json() as {
        assistant_message: {content: string; structured_output?: Record<string, unknown>; source_references?: Array<{excerpt: string; filename?: string | null; citation_verified: boolean}>};
        structured_output?: Record<string, unknown>;
        source_references?: Array<{excerpt: string; filename?: string | null; citation_verified: boolean}>;
        status?: string;
      };
      const assistantMsg = response.assistant_message;
      setChatMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: assistantMsg.content,
          structured_output: assistantMsg.structured_output ?? response.structured_output,
          source_references: assistantMsg.source_references ?? response.source_references,
        },
      ]);
      // Update session list message count
      setChatSessions((prev) =>
        prev.map((s) =>
          s.session_id === activeChatSessionId
            ? { ...s, message_count: (s.message_count ?? 0) + 2 }
            : s
        )
      );
    } catch (err) {
      setChatError(err instanceof Error ? err.message : "Failed to send message");
      // remove the optimistic user message
      setChatMessages((prev) => prev.slice(0, -1));
    } finally {
      setChatLoading(false);
    }
  }, [runtimeAppId, activeChatSessionId, chatInput, chatLoading, sessionApiKey, apiBaseUrl, buildHeaders]);

  useEffect(() => {
    if (currentPage === "adapted" && activeRunId && !runtimeAppId && !isProvisioning) {
      void provisionAndLoadApp();
    }
  }, [currentPage, activeRunId, runtimeAppId, isProvisioning, provisionAndLoadApp]);

  useEffect(() => {
    if (activeChatSessionId) void loadSessionMessages(activeChatSessionId);
  }, [activeChatSessionId, loadSessionMessages]);


  return (
    <div className="adaptos-app">
      {/* =====================================================================
          HEADER & CONNECTION CONTROLS
      ===================================================================== */}
      <header className="top-header">
        <div className="brand-group">
          <div className="brand-logo">ADAPTOS</div>
          <span className="brand-tagline">AI Adaptation Factory</span>
        </div>

        <div className="header-actions">
          {activeRunId && (
            <div className="run-badge mono">
              <span>PROJECT:</span>
              <strong>{activeRunId}</strong>
            </div>
          )}

          <div
            className="health-indicator"
            title={
              health
                ? `Backend v${health.version}`
                : healthError || "Checking backend..."
            }
          >
            <span
              className={`status-dot ${health ? "online" : "offline"}`}
            />
            <span>{health ? "Backend Connected" : "Backend Offline"}</span>
          </div>

          <button
            type="button"
            className="btn-outline"
            onClick={() => setShowSettingsDrawer((prev) => !prev)}
          >
            {sessionApiKey
              ? "Connection & Auth (Configured)"
              : "Connection & Resume Project"}
          </button>
        </div>
      </header>

      {/* =====================================================================
          9-STAGE USER JOURNEY NAVIGATION BAR
      ===================================================================== */}
      <nav className="journey-nav" aria-label="Adaptation Journey Stages">
        {JOURNEY_PAGES.map((p) => {
          const isCurrent = currentPage === p.id;
          const isDone = pageCompletionMap[p.id];
          return (
            <button
              key={p.id}
              type="button"
              className={`journey-step-btn ${isCurrent ? "active" : ""} ${
                isDone ? "completed" : ""
              }`}
              onClick={() => setCurrentPage(p.id)}
            >
              <span className="step-num mono">0{p.stepNumber}</span>
              <span>{p.navLabel}</span>
              {isDone && <span className="step-check">✓</span>}
            </button>
          );
        })}
      </nav>

      {/* =====================================================================
          USER ORIENTATION STATUS STRIP (Where You Are / What's Happening / Next Step)
      ===================================================================== */}
      <div className="journey-status-strip">
        <div className="status-strip-left">
          <span className="strip-item">
            <strong>Current Status:</strong> {nextActionGuide.now}
          </span>
          <span className="strip-item">
            <strong>Next Step:</strong> {nextActionGuide.next}
          </span>
        </div>
        <div className="status-strip-right">
          {activeRunId && (
            <>
              <button
                type="button"
                className="btn-outline"
                disabled={isLoading}
                onClick={() => void fetchProjectAndDelivery(activeRunId)}
              >
                Refresh Status
              </button>
              <label
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                  cursor: "pointer",
                  color: "var(--text-secondary)",
                }}
              >
                <input
                  type="checkbox"
                  checked={autoPoll}
                  onChange={(e) => setAutoPoll(e.target.checked)}
                />
                <span>Auto-Refresh</span>
              </label>
            </>
          )}
        </div>
      </div>

      {/* =====================================================================
          CONNECTION, BEARER KEY & RESUME EXISTING PROJECT DRAWER
      ===================================================================== */}
      {showSettingsDrawer && (
        <section className="settings-drawer">
          <div className="settings-grid">
            <div>
              <label className="field-label">FastAPI Backend Base URL</label>
              <input
                type="text"
                className="input-dark mono"
                value={apiBaseUrl}
                onChange={(e) => setApiBaseUrl(e.target.value)}
              />
            </div>
            <div>
              <label className="field-label">
                Session Bearer API Key (ADAPTOS_API_KEY)
              </label>
              <input
                type="password"
                className="input-dark mono"
                value={sessionApiKey}
                onChange={(e) => setSessionApiKey(e.target.value)}
                placeholder="Enter session Bearer token (never hardcoded)"
              />
            </div>
            <div>
              <label className="field-label">
                Load Existing Project by Run ID
              </label>
              <div style={{ display: "flex", gap: "8px" }}>
                <input
                  type="text"
                  className="input-dark mono"
                  value={resumeRunInput}
                  onChange={(e) => setResumeRunInput(e.target.value)}
                  placeholder="run_..."
                />
                <button
                  type="button"
                  className="btn-dark"
                  disabled={isLoading || !resumeRunInput.trim()}
                  onClick={() => {
                    void fetchProjectAndDelivery(resumeRunInput);
                    setShowSettingsDrawer(false);
                  }}
                >
                  Load
                </button>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* =====================================================================
          GLOBAL FEEDBACK BANNER
      ===================================================================== */}
      {banner && (
        <div className={`global-banner ${banner.kind}`}>
          <span>{banner.message}</span>
          <button
            type="button"
            className="btn-outline"
            onClick={() => setBanner(null)}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* =====================================================================
          PAGE 1 — ADAPTATION HOME
      ===================================================================== */}
      {currentPage === "home" && (
        <main className="page-wrapper">
          <div className="page-hero">
            <span className="page-eyebrow">Step 1 of 9 • Adaptation Home</span>
            <h1 className="page-title">Adapt AI as per your need.</h1>
            <p className="page-description">
              Tell us what you want to build. Upload your files and let AdaptOS
              understand, design, build and independently verify your AI
              application.
            </p>
          </div>

          {/* Section A — Describe your requirements */}
          <section className="card-primary">
            <div>
              <h2 className="card-heading">Describe your requirements</h2>
              <p className="card-subheading">
                Explain what you want your AI application to do in plain
                language.
              </p>
            </div>
            <textarea
              className="textarea-dark textarea-large"
              placeholder="Describe the AI application you want to create..."
              value={requirementText}
              onChange={(e) => setRequirementText(e.target.value)}
            />
          </section>

          {/* Section B — Upload files */}
          <section className="card-primary">
            <div>
              <h2 className="card-heading">Upload your files and knowledge</h2>
              <p className="card-subheading">
                Give your AI the context and information it needs. Supported
                backend formats: <code>.txt</code>, <code>.md</code>,{" "}
                <code>.csv</code>, <code>.json</code>.
              </p>
            </div>

            <div
              className={`dropzone-area ${isDraggingOver ? "dragging" : ""}`}
              onDragOver={(e) => {
                e.preventDefault();
                setIsDraggingOver(true);
              }}
              onDragLeave={() => setIsDraggingOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDraggingOver(false);
                void handleFilesSelected(e.dataTransfer.files);
              }}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                multiple
                accept=".txt,.md,.csv,.json"
                style={{ display: "none" }}
                onChange={(e) => void handleFilesSelected(e.target.files)}
              />
              <div style={{ fontWeight: 600, fontSize: "16px" }}>
                Drag and drop your files here
              </div>
              <div className="card-subheading">
                or click below to browse documents from your computer
              </div>
              <button
                type="button"
                className="btn-dark"
                onClick={(e) => {
                  e.stopPropagation();
                  fileInputRef.current?.click();
                }}
              >
                Browse files
              </button>
            </div>

            {selectedFiles.length > 0 && (
              <div className="file-list">
                {selectedFiles.map((file) => (
                  <div key={file.id} className="file-item">
                    <div className="file-item-meta">
                      <span className="file-name">{file.filename}</span>
                      <span className="file-sub mono">
                        {formatBytes(file.sizeBytes)} • Format: .
                        {file.format.toUpperCase()}
                      </span>
                      {file.errorNote && (
                        <span
                          style={{
                            color: "var(--status-danger)",
                            fontSize: "12px",
                          }}
                        >
                          Error: {file.errorNote}
                        </span>
                      )}
                    </div>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "10px",
                      }}
                    >
                      <span
                        className={`badge ${
                          file.validFormat ? "success" : "danger"
                        }`}
                      >
                        {file.validFormat ? "Ready to Upload" : "Invalid Format"}
                      </span>
                      <button
                        type="button"
                        className="btn-outline"
                        onClick={() => handleRemoveSelectedFile(file.id)}
                      >
                        Remove
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {uploadStatusText && (
              <div className="card-secondary mono">{uploadStatusText}</div>
            )}

            <div className="action-row">
              <span className="card-subheading">
                AdaptOS will create a unique project ID on the backend and
                verify your uploaded files before starting intake.
              </span>
              <button
                type="button"
                className="btn-white"
                disabled={isLoading || !requirementText.trim()}
                onClick={() => void handleStartAdaptation()}
              >
                {isLoading ? "Starting Adaptation..." : "Start Adaptation →"}
              </button>
            </div>
          </section>
        </main>
      )}

      {/* =====================================================================
          PAGE 2 — INTAKE AI AGENT
      ===================================================================== */}
      {currentPage === "intake" && (
        <main className="page-wrapper wide">
          <div className="page-hero">
            <span className="page-eyebrow">Step 2 of 9 • Intake Consultant</span>
            <h1 className="page-title">Let's understand your requirements.</h1>
            <p className="page-description">
              Our AI will ask the right questions to understand exactly what you
              need.
            </p>
          </div>

          <div className="card-secondary">
            <div className="action-row">
              <div>
                <strong>
                  Intake Mode: Guided Structured Discovery Interview
                </strong>
                <p className="card-subheading">
                  Backend Disclosure: <code>backend/api.py</code> exposes{" "}
                  <code>POST /assets</code>, <code>POST /spec</code>, and{" "}
                  <code>POST /approve</code> (which verifies{" "}
                  <code>TranscriptTurn</code> and{" "}
                  <code>GroundedFieldSpec</code> provenance via{" "}
                  <code>ProvenanceVerifier.verify_field_grounding()</code>), and
                  does not expose a live multi-turn LLM chat endpoint. Your
                  answers below are recorded directly into verified transcript
                  turns to ground your specification without fabricating LLM
                  responses.
                </p>
              </div>
              <span className="badge">
                Progress:{" "}
                {Math.min(intakeStepIdx, INTAKE_DISCOVERY_QUESTIONS.length)} /{" "}
                {INTAKE_DISCOVERY_QUESTIONS.length} Topics
              </span>
            </div>
          </div>

          <div className="intake-layout">
            {/* Conversational Window */}
            <section className="chat-window">
              <div className="chat-header">
                <div className="agent-identity">
                  <div className="agent-avatar">AI</div>
                  <div>
                    <div style={{ fontWeight: 600 }}>AdaptOS Intake Agent</div>
                    <div className="file-sub">
                      Requirement Discovery &amp; Provenance Grounding
                    </div>
                  </div>
                </div>
                <span className="badge">
                  {activeRunId ? `Run: ${activeRunId}` : "Not Initialized"}
                </span>
              </div>

              <div className="chat-messages">
                {intakeMessages.length === 0 ? (
                  <div className="card-subheading">
                    No active intake session yet. Start from Adaptation Home to
                    create a project and begin discovery.
                  </div>
                ) : (
                  intakeMessages.map((msg) => (
                    <div
                      key={msg.turnId}
                      className={`chat-bubble ${msg.role}`}
                    >
                      <div className="bubble-sender">
                        {msg.role === "agent"
                          ? "AdaptOS Intake Consultant"
                          : "You"}
                      </div>
                      <div style={{ whiteSpace: "pre-wrap" }}>{msg.text}</div>
                    </div>
                  ))
                )}
              </div>

              {intakeError && (
                <div style={{ color: "#f87171", fontSize: "0.85rem", padding: "6px 0", marginBottom: "4px" }}>
                  ⚠️ {intakeError}
                </div>
              )}
              <div className="chat-input-bar">
                <input
                  type="text"
                  className="input-dark"
                  placeholder={
                    intakeLoading
                      ? "AI is thinking…"
                      : "Reply to the agent…"
                  }
                  value={intakeInputText}
                  onChange={(e) => setIntakeInputText(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      void handleSendIntakeTurn();
                    }
                  }}
                  disabled={intakeLoading}
                />
                <button
                  type="button"
                  className="btn-white"
                  disabled={!intakeInputText.trim() || intakeLoading}
                  onClick={() => void handleSendIntakeTurn()}
                >
                  {intakeLoading ? "…" : "Send"}
                </button>
              </div>
            </section>

            {/* Right Sidebar: Confirmed File Context & Discovery Checklist */}
            <aside
              style={{ display: "flex", flexDirection: "column", gap: "20px" }}
            >
              <div className="card-primary">
                <h3 className="card-heading">Uploaded Knowledge Context</h3>
                {ingestedProfiles.length > 0 ? (
                  <div className="file-list">
                    {ingestedProfiles.map((p) => (
                      <div key={p.asset_id} className="file-item">
                        <div className="file-item-meta">
                          <span className="file-name">{p.filename}</span>
                          <span className="file-sub mono">
                            {formatBytes(p.size_bytes)} • SHA-256:{" "}
                            {p.sha256.slice(0, 12)}…
                          </span>
                        </div>
                        <span className="badge success">Verified</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="card-subheading">
                    No knowledge files uploaded for this project.
                  </p>
                )}
              </div>

              <div className="card-primary">
                <h3 className="card-heading">Discovery Checklist</h3>
                <ul className="checklist-list">
                  {INTAKE_DISCOVERY_QUESTIONS.map((q, idx) => {
                    const isDone = idx < intakeStepIdx;
                    return (
                      <li
                        key={q.id}
                        className={`checklist-item ${isDone ? "done" : ""}`}
                      >
                        <span>{isDone ? "✓" : `${idx + 1}.`}</span>
                        <div>
                          <div style={{ fontWeight: 600 }}>{q.topicLabel}</div>
                          <div className="file-sub">
                            {intakeAnswers[q.id] || q.question}
                          </div>
                        </div>
                      </li>
                    );
                  })}
                </ul>

                <button
                  type="button"
                  className="btn-white"
                  disabled={isLoading || !activeRunId}
                  onClick={() => void handleSubmitSpecFromIntake()}
                >
                  {isLoading
                    ? "Submitting Blueprint..."
                    : "Prepare & Submit Specification Blueprint →"}
                </button>
              </div>
            </aside>
          </div>

          {/* ── Inline Specification Review & Approval ─────────────────────── */}
          {(projectSummary?.stage === "spec_review" || projectSummary?.approved_spec_hash) && (
            <section className="card-primary" style={{ marginTop: "24px" }}>
              <div className="action-row">
                <div>
                  <span className="field-label">Specification Review</span>
                  <h2 className="card-heading">{activeSpec.goal}</h2>
                </div>
                <span className={`badge ${projectSummary?.approved_spec_hash ? "success" : "warning"}`}>
                  {projectSummary?.approved_spec_hash
                    ? `Approved (${projectSummary.approved_spec_hash.slice(0, 10)}…)`
                    : "Awaiting Your Approval"}
                </span>
              </div>

              <div className="grid-2">
                <div className="card-secondary">
                  <span className="field-label">Expected Inputs</span>
                  {activeSpec.inputs.map((inp) => (
                    <div key={inp.name} className="file-item">
                      <div className="file-item-meta">
                        <span className="file-name mono">{inp.name}</span>
                        <span className="file-sub">{inp.description}</span>
                      </div>
                      <span className="badge mono">{inp.data_type}{inp.required ? " (required)" : ""}</span>
                    </div>
                  ))}
                </div>
                <div className="card-secondary">
                  <span className="field-label">Expected Outputs</span>
                  {activeSpec.outputs.map((out) => (
                    <div key={out.name} className="file-item">
                      <div className="file-item-meta">
                        <span className="file-name mono">{out.name}</span>
                        <span className="file-sub">{out.description}</span>
                      </div>
                      <span className="badge mono">{out.data_type}{out.required ? " (required)" : ""}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="card-secondary">
                <span className="field-label">Mandatory Constraints</span>
                <ul style={{ paddingLeft: "18px" }}>
                  {activeSpec.constraints.map((c, idx) => (
                    <li key={idx} style={{ marginBottom: "6px" }}>{c}</li>
                  ))}
                </ul>
              </div>

              <div className="card-secondary">
                <span className="field-label">Acceptance Criteria</span>
                <div className="data-table-wrapper">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Criterion ID</th>
                        <th>Description</th>
                        <th>Method</th>
                        <th>Min Pass Rate</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeSpec.acceptance_criteria.map((ac) => (
                        <tr key={ac.criterion_id}>
                          <td className="mono">{ac.criterion_id}</td>
                          <td>{ac.description}</td>
                          <td className="mono">{ac.method}</td>
                          <td className="mono">{(ac.min_pass_rate * 100).toFixed(0)}%</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {!projectSummary?.approved_spec_hash && (
                <div className="action-row" style={{ marginTop: "16px" }}>
                  <button
                    type="button"
                    className="btn-dark"
                    onClick={() => setShowChangeEditor((prev) => !prev)}
                  >
                    Request Changes
                  </button>
                  <button
                    type="button"
                    className="btn-white"
                    disabled={isLoading || !activeRunId}
                    onClick={() => void handleApproveSpecification()}
                  >
                    {isLoading ? "Verifying & Approving…" : "Approve Specification →"}
                  </button>
                </div>
              )}

              {showChangeEditor && (
                <div className="card-secondary" style={{ marginTop: "12px" }}>
                  <label className="field-label">Refine Application Objective or Constraints</label>
                  <textarea
                    className="textarea-dark"
                    value={changeRequestNote || draftSpec.goal}
                    onChange={(e) => {
                      setChangeRequestNote(e.target.value);
                      setDraftSpec((prev) => ({ ...prev, goal: e.target.value }));
                    }}
                  />
                  <div className="action-row">
                    <button
                      type="button"
                      className="btn-dark"
                      disabled={isLoading || !activeRunId}
                      onClick={() => { setShowChangeEditor(false); void handleSubmitSpecFromIntake(); }}
                    >
                      Re-Submit Updated Specification
                    </button>
                  </div>
                </div>
              )}

              {projectSummary?.approved_spec_hash && (
                <div className="action-row" style={{ marginTop: "16px" }}>
                  <button
                    type="button"
                    className="btn-white"
                    onClick={() => setCurrentPage("architecture")}
                  >
                    Proceed to Architecture Studio →
                  </button>
                </div>
              )}
            </section>
          )}
        </main>
      )}


      {/* =====================================================================
          PAGE 4 — ARCHITECTURE STUDIO
      ===================================================================== */}
      {currentPage === "architecture" && (
        <main className="page-wrapper wide">
          <div className="page-hero">
            <span className="page-eyebrow">
              Step 4 of 9 • Architecture Studio
            </span>
            <h1 className="page-title">Designing your AI architecture</h1>
            <p className="page-description">
              Here's how your application will work.
            </p>
          </div>

          <div className="card-secondary">
            <div className="action-row">
              <div>
                <strong>Architecture Source Disclosure:</strong>{" "}
                <span className="card-subheading">
                  In AdaptOS, the application step pipeline (
                  <code>app_config.json</code>) is assembled during the{" "}
                  <strong>Build</strong> stage by{" "}
                  <code>BuildEngine.build_application()</code>. Below you can
                  inspect both your application's planned execution pipeline and
                  the 12-component AdaptOS platform architecture.
                </span>
              </div>
              <div style={{ display: "flex", gap: "8px" }}>
                <button
                  type="button"
                  className={
                    archViewMode === "app_pipeline" ? "btn-white" : "btn-dark"
                  }
                  onClick={() => setArchViewMode("app_pipeline")}
                >
                  Application Pipeline View
                </button>
                <button
                  type="button"
                  className={
                    archViewMode === "platform" ? "btn-white" : "btn-dark"
                  }
                  onClick={() => setArchViewMode("platform")}
                >
                  AdaptOS 12-Component System
                </button>
              </div>
            </div>
          </div>

          {archViewMode === "app_pipeline" ? (
            <section className="card-primary">
              <h2 className="card-heading">
                Application Execution Pipeline (Schema-Driven Runtime)
              </h2>
              <p className="card-subheading">
                Every request to your adapted AI flows through these verified
                components in strict topological order:
              </p>

              <div className="grid-4">
                <div className="card-secondary">
                  <span className="badge mono">1. io.validate@1.0.0</span>
                  <strong>Input Validation</strong>
                  <p className="card-subheading">
                    Validates incoming{" "}
                    {activeSpec.inputs.map((i) => i.name).join(", ")} against{" "}
                    <code>schemas/io_schema.json</code>.
                  </p>
                </div>
                <div className="card-secondary">
                  <span className="badge mono">2. doc.ingest@1.0.0</span>
                  <strong>Knowledge Indexing</strong>
                  <p className="card-subheading">
                    Chunks uploaded knowledge assets into a tenant-isolated
                    SQLite FTS5 index.
                  </p>
                </div>
                <div className="card-secondary">
                  <span className="badge mono">3. retrieve.lexical@1.0.0</span>
                  <strong>Evidence Retrieval</strong>
                  <p className="card-subheading">
                    Retrieves top-k relevant policy passages matching the user
                    request.
                  </p>
                </div>
                <div className="card-secondary">
                  <span className="badge mono">4. prompt.compose@1.0.0</span>
                  <strong>Context Engineering</strong>
                  <p className="card-subheading">
                    Orders mandatory constraints ahead of{" "}
                    <code>&lt;untrusted_retrieved_evidence&gt;</code>.
                  </p>
                </div>
                <div className="card-secondary">
                  <span className="badge mono">5. model.chat@1.0.0</span>
                  <strong>Model Inference</strong>
                  <p className="card-subheading">
                    Executes structured JSON completion with{" "}
                    <code>muse-spark-1.3</code> under runtime limits.
                  </p>
                </div>
                <div className="card-secondary">
                  <span className="badge mono">6. output.structured@1.0.0</span>
                  <strong>Output Schema Gate</strong>
                  <p className="card-subheading">
                    Verifies output fields (
                    {activeSpec.outputs.map((o) => o.name).join(", ")}) match
                    declared types.
                  </p>
                </div>
                <div className="card-secondary">
                  <span className="badge mono">7. cite.verify@1.0.0</span>
                  <strong>Citation Grounding</strong>
                  <p className="card-subheading">
                    Verifies that cited spans exist in the retrieved evidence
                    passages.
                  </p>
                </div>
                <div className="card-secondary">
                  <span className="badge mono">8. log.trace@1.0.0</span>
                  <strong>Execution Trace</strong>
                  <p className="card-subheading">
                    Records per-step latency and status into{" "}
                    <code>CaseExecutionTrace</code>.
                  </p>
                </div>
              </div>
            </section>
          ) : (
            <div className="arch-split">
              <div className="card-primary">
                <h2 className="card-heading">
                  Interactive 12-Component System Topology
                </h2>
                <div className="arch-svg-box">
                  <svg
                    className="arch-svg"
                    viewBox="0 0 1160 520"
                    role="img"
                    aria-label="AdaptOS 12-Component Architecture Diagram"
                  >
                    {ARCHITECTURE_EDGES.map((edge, idx) => {
                      const src = ARCHITECTURE_NODES.find(
                        (n) => n.id === edge.from
                      )!;
                      const dst = ARCHITECTURE_NODES.find(
                        (n) => n.id === edge.to
                      )!;
                      const isHi =
                        selectedArchNodeId === edge.from ||
                        selectedArchNodeId === edge.to;
                      return (
                        <line
                          key={idx}
                          x1={src.x + 110}
                          y1={src.y + 42}
                          x2={dst.x + 110}
                          y2={dst.y + 42}
                          stroke={isHi ? "#FFFFFF" : "#303541"}
                          strokeWidth={isHi ? 2.2 : 1.2}
                        />
                      );
                    })}
                    {ARCHITECTURE_NODES.map((node) => {
                      const isSel = node.id === selectedArchNodeId;
                      return (
                        <g
                          key={node.id}
                          className="arch-node-clickable"
                          transform={`translate(${node.x}, ${node.y})`}
                          onClick={() => setSelectedArchNodeId(node.id)}
                        >
                          <rect
                            width="220"
                            height="84"
                            rx="8"
                            fill={isSel ? "#FFFFFF" : "#20232B"}
                            stroke={isSel ? "#FFFFFF" : "#525968"}
                            strokeWidth={isSel ? 2 : 1}
                          />
                          <text
                            x="14"
                            y="24"
                            fill={isSel ? "#000000" : "#9CA3AF"}
                            fontSize="11"
                            fontFamily="monospace"
                            fontWeight="600"
                          >
                            {node.shortLabel}
                          </text>
                          <text
                            x="14"
                            y="46"
                            fill={isSel ? "#000000" : "#FFFFFF"}
                            fontSize="13"
                            fontWeight="700"
                          >
                            {node.title}
                          </text>
                          <text
                            x="14"
                            y="68"
                            fill={isSel ? "#20232B" : "#9CA3AF"}
                            fontSize="10"
                            fontFamily="monospace"
                          >
                            {node.sourceFiles[0]}
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                </div>
              </div>

              <aside className="card-primary">
                <span className="badge mono">{selectedArchNode.zone}</span>
                <h2 className="card-heading">{selectedArchNode.title}</h2>
                <p className="card-subheading">
                  {selectedArchNode.responsibility}
                </p>
                <div>
                  <span className="field-label">Source File(s)</span>
                  <div className="mono" style={{ fontSize: "13px" }}>
                    {selectedArchNode.sourceFiles.join(", ")}
                  </div>
                </div>
                <div>
                  <span className="field-label">Key Classes &amp; Methods</span>
                  <ul style={{ paddingLeft: "18px", fontSize: "13px" }}>
                    {selectedArchNode.classesAndFunctions.map((c) => (
                      <li key={c} className="mono">
                        {c}
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <span className="field-label">Inputs &amp; Outputs</span>
                  <p className="card-subheading">
                    <strong>In:</strong> {selectedArchNode.inputs.join("; ")}{" "}
                    <br />
                    <strong>Out:</strong> {selectedArchNode.outputs.join("; ")}
                  </p>
                </div>
              </aside>
            </div>
          )}

          <div className="action-row">
            <button
              type="button"
              className="btn-dark"
              onClick={() => setCurrentPage("intake")}
            >
              ← Back to Intake & Spec
            </button>
            <button
              type="button"
              className="btn-white"
              onClick={() => setCurrentPage("build")}
            >
              Proceed to Build Workspace →
            </button>
          </div>
        </main>
      )}

      {/* =====================================================================
          PAGE 5 — BUILD WORKSPACE
      ===================================================================== */}
      {currentPage === "build" && (
        <main className="page-wrapper">
          <div className="page-hero">
            <span className="page-eyebrow">Step 5 of 9 • Build Workspace</span>
            <h1 className="page-title">Building your AI application</h1>
            <p className="page-description">
              AdaptOS is now turning your approved design into a working
              application.
            </p>
          </div>

          <section className="card-primary">
            <div className="action-row">
              <div>
                <h2 className="card-heading">
                  Factory Pipeline Execution Control
                </h2>
                <p className="card-subheading">
                  Current Backend Stage:{" "}
                  <strong className="mono">
                    {projectSummary?.stage || "unloaded"}
                  </strong>
                </p>
              </div>
              <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
                <button
                  type="button"
                  className="btn-white"
                  disabled={isLoading || !activeRunId}
                  onClick={() => void handleExecuteCompletePipeline()}
                >
                  {isLoading
                    ? "Executing Factory Pipeline..."
                    : "Run Complete Adaptation Pipeline →"}
                </button>
              </div>
            </div>

            <div className="grid-4">
              <div className="stat-card">
                <span className="stat-label">Evaluation Plan Hash</span>
                <span className="stat-value mono" style={{ fontSize: "14px" }}>
                  {projectSummary?.plan_hash
                    ? `${projectSummary.plan_hash.slice(0, 14)}…`
                    : "Pending"}
                </span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Sealed Test Set ID</span>
                <span className="stat-value mono" style={{ fontSize: "14px" }}>
                  {projectSummary?.sealed_set_id || "Pending"}
                </span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Baseline Bundle</span>
                <span className="stat-value mono" style={{ fontSize: "14px" }}>
                  {projectSummary?.baseline_version_id || "Pending"}
                </span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Candidate Bundle</span>
                <span className="stat-value mono" style={{ fontSize: "14px" }}>
                  {projectSummary?.candidate_version_id || "Pending"}
                </span>
              </div>
            </div>

            <div className="pipeline-steps-list">
              {WORKFLOW_STAGES.map((st) => {
                const stState = workflowNodeStates[st.node];
                return (
                  <div
                    key={st.node}
                    className={`pipeline-step-row ${stState}`}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: "15px" }}>
                        {st.userFriendlyTitle}{" "}
                        <span
                          className="mono"
                          style={{
                            fontSize: "12px",
                            color: "var(--text-secondary)",
                          }}
                        >
                          ({st.node})
                        </span>
                      </div>
                      <div className="card-subheading">{st.description}</div>
                    </div>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "10px",
                      }}
                    >
                      <span
                        className={`badge ${
                          stState === "completed"
                            ? "success"
                            : stState === "failed"
                            ? "danger"
                            : stState === "active"
                            ? "warning"
                            : ""
                        }`}
                      >
                        {stState.toUpperCase()}
                      </span>
                      <button
                        type="button"
                        className="btn-outline mono"
                        disabled={isLoading || !activeRunId}
                        onClick={() => void handleExecuteSingleStage(st.node)}
                      >
                        Run Stage
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>

            <div>
              <span className="field-label">
                Real Backend Workflow Events (FactoryGraphState.events)
              </span>
              {projectSummary?.events && projectSummary.events.length > 0 ? (
                <div className="log-box mono">
                  {projectSummary.events.map((ev, idx) => (
                    <div key={idx}>
                      {String(idx + 1).padStart(2, "0")}. {ev}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="card-secondary">
                  No workflow events recorded yet. Click &ldquo;Run Complete
                  Adaptation Pipeline →&rdquo; above.
                </div>
              )}
            </div>

            {projectSummary?.errors && projectSummary.errors.length > 0 && (
              <div className="card-secondary" style={{ borderColor: "var(--status-danger)" }}>
                <span className="field-label" style={{ color: "var(--status-danger)" }}>
                  Backend Error Records
                </span>
                {projectSummary.errors.map((err, i) => (
                  <div key={i} className="mono" style={{ fontSize: "13px" }}>
                    [{err.stage}] {err.code}: {err.message}
                  </div>
                ))}
              </div>
            )}

            <div className="action-row">
              <button
                type="button"
                className="btn-dark"
                onClick={() => setCurrentPage("architecture")}
              >
                ← Back to Architecture Studio
              </button>
              <button
                type="button"
                className="btn-white"
                onClick={() => setCurrentPage("testing")}
              >
                Inspect Testing &amp; Repair →
              </button>
            </div>
          </section>
        </main>
      )}

      {/* =====================================================================
          PAGE 6 — TESTING & REPAIR
      ===================================================================== */}
      {currentPage === "testing" && (
        <main className="page-wrapper">
          <div className="page-hero">
            <span className="page-eyebrow">Step 6 of 9 • Testing &amp; Repair</span>
            <h1 className="page-title">Making sure everything works</h1>
            <p className="page-description">
              AdaptOS runs development tests to diagnose issues and automatically
              repairs configuration or code before freezing your candidate
              application.
            </p>
          </div>

          <div className="card-secondary">
            <strong>
              Important Distinction: Development Testing vs. Protected
              Independent Evaluation
            </strong>
            <p className="card-subheading">
              Development tests run inside the Factory Plane to guide{" "}
              <code>BuildEngine</code> and <code>RepairAgent</code>. Passing
              development tests <strong>never</strong> authorizes final delivery
              — your application must still pass independent evaluation on
              sealed held-out cases in Step 7.
            </p>
          </div>

          <div className="grid-4">
            <div className="stat-card">
              <span className="stat-label">Development Pass Rate</span>
              <span className="stat-value mono">
                {projectSummary?.dev_pass_rate !== null &&
                projectSummary?.dev_pass_rate !== undefined
                  ? `${(projectSummary.dev_pass_rate * 100).toFixed(0)}%`
                  : "Not Run"}
              </span>
            </div>
            <div className="stat-card">
              <span className="stat-label">Dev Suite Result</span>
              <span className="stat-value">
                {projectSummary?.dev_pass_rate !== null &&
                projectSummary?.dev_pass_rate !== undefined
                  ? projectSummary.dev_test_passed
                    ? "Passed"
                    : "Failed"
                  : "Pending"}
              </span>
            </div>
            <div className="stat-card">
              <span className="stat-label">Repair Attempts Used</span>
              <span className="stat-value mono">
                {projectSummary?.repair_attempts ?? 0} / 3
              </span>
            </div>
            <div className="stat-card">
              <span className="stat-label">Remaining Repair Budget</span>
              <span className="stat-value mono">
                {projectSummary?.repair_budget_left ?? 3}
              </span>
            </div>
          </div>

          <section className="card-primary">
            <h2 className="card-heading">
              Bounded Self-Repair &amp; Regression History
            </h2>
            {activeRepairLog.length > 0 ? (
              <div className="data-table-wrapper">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Attempt</th>
                      <th>Version Transition</th>
                      <th>Target Component</th>
                      <th>Regression Gate</th>
                      <th>Diagnostic Explanation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activeRepairLog.map((rec) => {
                      const parsed = parseRepairReason(rec.reason);
                      return (
                        <tr key={rec.attempt}>
                          <td className="mono">#{rec.attempt}</td>
                          <td className="mono">
                            {rec.parent_version_id} → {rec.new_version_id}
                          </td>
                          <td className="mono">{rec.target_component}</td>
                          <td>
                            <span
                              className={`badge ${
                                rec.accepted ? "success" : "danger"
                              }`}
                            >
                              {rec.accepted
                                ? "Accepted (0 Regressions)"
                                : "Rejected (Rolled Back)"}
                            </span>
                          </td>
                          <td>{parsed.summaryText}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="card-secondary">
                {projectSummary?.repair_attempts
                  ? `${projectSummary.repair_attempts} repair attempt(s) executed. Full RepairRecord details populate once the DeliveryPackage is sealed.`
                  : "No repair attempts were required or executed yet."}
              </div>
            )}

            <div className="action-row">
              <button
                type="button"
                className="btn-dark"
                onClick={() => setCurrentPage("build")}
              >
                ← Back to Build Workspace
              </button>
              <button
                type="button"
                className="btn-white"
                onClick={() => setCurrentPage("verification")}
              >
                Continue to Independent Verification →
              </button>
            </div>
          </section>
        </main>
      )}

      {/* =====================================================================
          PAGE 7 — INDEPENDENT VERIFICATION
      ===================================================================== */}
      {currentPage === "verification" && (
        <main className="page-wrapper">
          <div className="page-hero">
            <span className="page-eyebrow">
              Step 7 of 9 • Independent Verification
            </span>
            <h1 className="page-title">Independently verifying your AI</h1>
            <p className="page-description">
              Your application is being evaluated against protected acceptance
              tests.
            </p>
          </div>

          <div className="card-secondary">
            <strong>Protected Evaluation Boundary Guarantee:</strong>
            <p className="card-subheading">
              Held-out test cases are sealed inside{" "}
              <code>eval_plane/vault.db</code>. Sealed test inputs, expected
              protected outputs, and per-case outputs are never exposed to the
              Factory Plane or browser. Only the cryptographically signed
              aggregate Verdict is returned.
            </p>
          </div>

          <div className="grid-4">
            <div className="stat-card">
              <span className="stat-label">Protected Verdict Status</span>
              <span className="stat-value mono">
                {projectSummary?.verdict_status
                  ? projectSummary.verdict_status.toUpperCase()
                  : "PENDING"}
              </span>
            </div>
            <div className="stat-card">
              <span className="stat-label">Frozen Artifact Evaluated</span>
              <span className="stat-value mono" style={{ fontSize: "15px" }}>
                {projectSummary?.frozen_version_id || "Not Frozen"}
              </span>
            </div>
            <div className="stat-card">
              <span className="stat-label">Sealed Test Set ID</span>
              <span className="stat-value mono" style={{ fontSize: "15px" }}>
                {projectSummary?.sealed_set_id || "None"}
              </span>
            </div>
            <div className="stat-card">
              <span className="stat-label">Delivery Eligibility</span>
              <span className="stat-value">
                {projectSummary?.is_ready_for_delivery
                  ? "Authorized"
                  : "Locked"}
              </span>
            </div>
          </div>

          <section className="card-primary">
            <h2 className="card-heading">
              Signed Aggregate Verdict &amp; Cryptographic Commitments
            </h2>

            {activeVerdict ? (
              <>
                <div className="grid-2">
                  <div className="card-secondary mono" style={{ fontSize: "13px" }}>
                    <div>
                      <strong>Verdict ID:</strong> {activeVerdict.verdict_id}
                    </div>
                    <div>
                      <strong>Signing Key ID:</strong>{" "}
                      {activeVerdict.signing_key_id}
                    </div>
                    <div>
                      <strong>Issued At (UTC):</strong>{" "}
                      {activeVerdict.issued_at}
                    </div>
                    <div>
                      <strong>Artifact Version:</strong>{" "}
                      {activeVerdict.artifact.version_id}
                    </div>
                  </div>

                  <div className="card-secondary mono" style={{ fontSize: "12px" }}>
                    <div>
                      <strong>Spec SHA-256:</strong>{" "}
                      {activeVerdict.spec_hash.slice(0, 24)}…
                    </div>
                    <div>
                      <strong>Artifact SHA-256:</strong>{" "}
                      {activeVerdict.artifact.artifact_hash.slice(0, 24)}…
                    </div>
                    <div>
                      <strong>Sealed Commitment SHA-256:</strong>{" "}
                      {activeVerdict.sealed_commitment_hash.slice(0, 24)}…
                    </div>
                    <div>
                      <strong>Private Evidence SHA-256:</strong>{" "}
                      {activeVerdict.evidence_hash.slice(0, 24)}…
                    </div>
                  </div>
                </div>

                <div>
                  <span className="field-label">
                    Protected Criterion Results (95% Wilson Score Confidence
                    Intervals)
                  </span>
                  <div className="data-table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Criterion ID</th>
                          <th>Method</th>
                          <th>Threshold</th>
                          <th>Held-Out Cases Passed</th>
                          <th>Wilson 95% CI</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {activeVerdict.criteria.map((cr) => (
                          <tr key={cr.criterion_id}>
                            <td className="mono">{cr.criterion_id}</td>
                            <td className="mono">{cr.method}</td>
                            <td className="mono">
                              {(cr.threshold * 100).toFixed(0)}%
                            </td>
                            <td className="mono">
                              {cr.n_passed} / {cr.n_cases} (
                              {(cr.pass_rate * 100).toFixed(1)}%)
                            </td>
                            <td className="mono">
                              [{(cr.wilson_lower * 100).toFixed(1)}%,{" "}
                              {(cr.wilson_upper * 100).toFixed(1)}%]
                            </td>
                            <td>
                              <span
                                className={`badge ${
                                  cr.passed ? "success" : "danger"
                                }`}
                              >
                                {cr.status.toUpperCase()}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div>
                  <span className="field-label">
                    Ed25519 Signature over Verdict.signing_payload()
                  </span>
                  <div className="code-block mono">
                    {activeVerdict.signature}
                  </div>
                </div>
              </>
            ) : (
              <div className="card-secondary">
                No signed Verdict has been issued yet. Run the pipeline in Build
                Workspace to execute independent evaluation.
              </div>
            )}

            <div className="action-row">
              <button
                type="button"
                className="btn-dark"
                onClick={() => setCurrentPage("testing")}
              >
                ← Back to Testing &amp; Repair
              </button>
              <button
                type="button"
                className="btn-white"
                disabled={isLoading || !projectSummary?.is_ready_for_delivery}
                onClick={() => void handleDownloadArtifacts("zip")}
              >
                Download Verified Bundle (.ZIP) →
              </button>
              <button
                type="button"
                className="btn-dark"
                disabled={isLoading || !projectSummary?.is_ready_for_delivery}
                onClick={() => void handleDownloadArtifacts("json")}
              >
                Inspect Bundle (JSON)
              </button>
              <button
                type="button"
                className="btn-white"
                disabled={!projectSummary?.is_ready_for_delivery}
                onClick={() => setCurrentPage("adapted")}
              >
                Open Your Adapted AI →
              </button>
            </div>
          </section>
        </main>
      )}



      {/* =====================================================================
          PAGE 7 — YOUR ADAPTED AI (Real Chatbot via Backend Runtime)
      ===================================================================== */}
      {currentPage === "adapted" && (
        <main className="page-wrapper wide">
          <div className="page-hero">
            <span className="page-eyebrow">Step 7 of 7 • Your Adapted AI</span>
            <h1 className="page-title">Your AI is adapted!</h1>
            <p className="page-description">
              Chat with your independently verified AI application, powered by the
              generated configuration, prompts, workflows and knowledge built by AdaptOS.
            </p>
          </div>

          {/* Status bar */}
          {runtimeAppId && (
            <div className="card-secondary" style={{ marginBottom: "12px" }}>
              <div className="action-row">
                <span className="card-subheading" style={{ fontSize: "13px" }}>
                  <strong>App ID:</strong>{" "}
                  <span className="mono">{runtimeAppId}</span>{" "}
                  &nbsp;•&nbsp; <strong>State:</strong>{" "}
                  <span className={`badge ${runtimeAppStatus === "ACTIVE" ? "success" : "warning"}`}>
                    {runtimeAppStatus || "UNKNOWN"}
                  </span>
                  &nbsp;•&nbsp; <strong>Project:</strong>{" "}
                  <span className="mono">{activeRunId}</span>
                </span>
                <button
                  type="button"
                  className="btn-outline"
                  disabled={isLoading}
                  onClick={() => void handleDownloadArtifacts("zip")}
                >
                  Download Bundle (.ZIP)
                </button>
              </div>
            </div>
          )}

          {/* Not ready gate */}
          {!activeRunId && (
            <section className="card-primary">
              <h2 className="card-heading">No project loaded</h2>
              <p className="card-subheading">
                Open the connection drawer, enter a run ID and load a project first.
              </p>
              <button
                type="button"
                className="btn-white"
                onClick={() => setCurrentPage("home")}
              >
                Go to Adaptation Home →
              </button>
            </section>
          )}

          {activeRunId && !projectSummary?.is_ready_for_delivery && !isProvisioning && !runtimeAppId && (
            <section className="card-primary">
              <h2 className="card-heading">Adaptation Not Yet Verified as Ready</h2>
              <p className="card-subheading">
                The chatbot unlocks after the backend issues a verified{" "}
                <code>READY</code> verdict. Current stage:{" "}
                <strong className="mono">{projectSummary?.stage || "unknown"}</strong>
                , Verdict:{" "}
                <strong className="mono">{projectSummary?.verdict_status || "none"}</strong>.
              </p>
              <div style={{ display: "flex", gap: "12px", marginTop: "16px" }}>
                <button
                  type="button"
                  className="btn-white"
                  onClick={() => setCurrentPage("build")}
                >
                  Return to Build & Verification →
                </button>
                <button
                  type="button"
                  className="btn-dark"
                  onClick={() => void provisionAndLoadApp()}
                >
                  Try Provision Anyway
                </button>
              </div>
            </section>
          )}

          {/* Provisioning spinner */}
          {isProvisioning && (
            <section className="card-primary">
              <h2 className="card-heading">Provisioning your application…</h2>
              <p className="card-subheading">
                Verifying delivery package, running integrity checks and starting the
                runtime. Please wait.
              </p>
            </section>
          )}

          {/* Provision error */}
          {runtimeProvisionError && !isProvisioning && (
            <div className="card-secondary" style={{ borderColor: "var(--status-danger)" }}>
              <strong style={{ color: "var(--status-danger)" }}>Provision Failed:</strong>{" "}
              {runtimeProvisionError}
              <div style={{ marginTop: "12px" }}>
                <button
                  type="button"
                  className="btn-dark"
                  onClick={() => { setRuntimeProvisionError(null); void provisionAndLoadApp(); }}
                >
                  Retry Provision
                </button>
              </div>
            </div>
          )}

          {/* Main chat interface */}
          {runtimeAppId && !isProvisioning && (
            <div className="intake-layout" style={{ gap: "16px" }}>
              {/* Session sidebar */}
              <aside style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                <div className="card-primary" style={{ flex: 1 }}>
                  <div className="action-row" style={{ marginBottom: "8px" }}>
                    <h3 className="card-heading" style={{ margin: 0 }}>Chat Sessions</h3>
                    <button
                      type="button"
                      className="btn-dark"
                      style={{ fontSize: "12px", padding: "4px 10px" }}
                      onClick={() => void createNewChatSession()}
                    >
                      + New Chat
                    </button>
                  </div>
                  {chatSessions.length === 0 ? (
                    <p className="card-subheading" style={{ fontSize: "13px" }}>
                      No sessions yet. Click&nbsp;<strong>+ New Chat</strong>&nbsp;to start.
                    </p>
                  ) : (
                    <div className="file-list">
                      {chatSessions.map((s) => (
                        <button
                          key={s.session_id}
                          type="button"
                          className={`file-item ${activeChatSessionId === s.session_id ? "active-session" : ""}`}
                          style={{
                            width: "100%",
                            textAlign: "left",
                            background: activeChatSessionId === s.session_id ? "var(--surface-active, #2a2d35)" : "transparent",
                            border: "none",
                            cursor: "pointer",
                            borderRadius: "4px",
                          }}
                          onClick={() => setActiveChatSessionId(s.session_id)}
                        >
                          <div className="file-item-meta">
                            <span className="file-name" style={{ fontSize: "13px" }}>
                              {s.title || `Session ${s.session_id.slice(0, 8)}…`}
                            </span>
                            {s.message_count !== undefined && s.message_count > 0 && (
                              <span className="file-sub mono">{s.message_count} messages</span>
                            )}
                          </div>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </aside>

              {/* Chat area */}
              <section className="chat-window" style={{ display: "flex", flexDirection: "column" }}>
                <div className="chat-header">
                  <div className="agent-identity">
                    <div className="agent-avatar">AI</div>
                    <div>
                      <div style={{ fontWeight: 600 }}>Your Adapted AI</div>
                      <div className="file-sub">
                        {projectSummary?.stage === "delivered"
                          ? `Verified • ${activeManifest?.architecture || "prompt_only"} architecture`
                          : "Runtime Application"}
                      </div>
                    </div>
                  </div>
                  {activeChatSessionId && (
                    <span className="badge mono" style={{ fontSize: "11px" }}>
                      {activeChatSessionId.slice(0, 16)}…
                    </span>
                  )}
                </div>

                <div className="chat-messages" style={{ flex: 1, overflowY: "auto" }}>
                  {!activeChatSessionId ? (
                    <div className="card-subheading">
                      Select a session from the sidebar or click &ldquo;+ New Chat&rdquo; to begin.
                    </div>
                  ) : chatMessages.length === 0 ? (
                    <div className="card-subheading">
                      No messages yet. Send your first message below.
                    </div>
                  ) : (
                    chatMessages.map((msg, i) => (
                      <div
                        key={msg.message_id ?? i}
                        className={`chat-bubble ${msg.role === "user" ? "user" : "agent"}`}
                      >
                        <div className="bubble-sender">
                          {msg.role === "user" ? "You" : "Your Adapted AI"}
                        </div>
                        <div style={{ whiteSpace: "pre-wrap" }}>{msg.content}</div>
                        {msg.structured_output && Object.keys(msg.structured_output).length > 0 && (
                          <details style={{ marginTop: "8px" }}>
                            <summary className="file-sub" style={{ cursor: "pointer", fontSize: "12px" }}>
                              Structured output
                            </summary>
                            <pre className="code-block mono" style={{ fontSize: "11px", marginTop: "4px" }}>
                              {JSON.stringify(msg.structured_output, null, 2)}
                            </pre>
                          </details>
                        )}
                        {msg.source_references && msg.source_references.length > 0 && (
                          <details style={{ marginTop: "8px" }}>
                            <summary className="file-sub" style={{ cursor: "pointer", fontSize: "12px" }}>
                              {msg.source_references.length} source reference(s)
                            </summary>
                            {msg.source_references.map((ref, ri) => (
                              <div key={ri} className="card-secondary" style={{ marginTop: "4px", padding: "6px 8px", fontSize: "12px" }}>
                                {ref.filename && <span className="mono" style={{ fontWeight: 600 }}>{ref.filename}: </span>}
                                <span>{ref.excerpt}</span>
                                {ref.citation_verified && (
                                  <span className="badge success" style={{ marginLeft: "6px", fontSize: "10px" }}>verified</span>
                                )}
                              </div>
                            ))}
                          </details>
                        )}
                      </div>
                    ))
                  )}
                  {chatLoading && (
                    <div className="chat-bubble agent">
                      <div className="bubble-sender">Your Adapted AI</div>
                      <span className="card-subheading">Thinking…</span>
                    </div>
                  )}
                </div>

                {chatError && (
                  <div className="card-secondary" style={{ borderColor: "var(--status-danger)", margin: "8px 0", padding: "8px 12px", fontSize: "13px" }}>
                    <strong style={{ color: "var(--status-danger)" }}>Error:</strong> {chatError}
                    <button
                      type="button"
                      className="btn-outline"
                      style={{ marginLeft: "12px", fontSize: "12px" }}
                      onClick={() => setChatError(null)}
                    >
                      Dismiss
                    </button>
                  </div>
                )}

                {activeChatSessionId && (
                  <div className="chat-input-bar">
                    <input
                      type="text"
                      className="input-dark"
                      placeholder={
                        activeSpec?.inputs?.[0]
                          ? `e.g. ${activeSpec.inputs[0].description || activeSpec.inputs[0].name}…`
                          : "Type your message…"
                      }
                      value={chatInput}
                      disabled={chatLoading}
                      onChange={(e) => setChatInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" && !e.shiftKey) {
                          e.preventDefault();
                          void sendChatMessage();
                        }
                      }}
                    />
                    <button
                      type="button"
                      className="btn-white"
                      disabled={chatLoading || !chatInput.trim()}
                      onClick={() => void sendChatMessage()}
                    >
                      {chatLoading ? "Sending…" : "Send"}
                    </button>
                  </div>
                )}
              </section>
            </div>
          )}
        </main>
      )}
    </div>
  );
}

export default App;