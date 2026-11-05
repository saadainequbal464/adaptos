// frontend/src/typesAndArchitectureData.ts
// Exact TypeScript contracts aligned with backend/api.py, service.py, schemas.py,
// graph.py, intake.py, eval_designer.py, builder.py, runtime.py, sandbox.py,
// repair.py, and eval_plane/evaluator.py.

export type Stage =
  | "intake"
  | "spec_review"
  | "eval_design"
  | "building"
  | "dev_testing"
  | "repairing"
  | "frozen"
  | "evaluating"
  | "verdict_issued"
  | "delivered"
  | "failed";

export type StageNodeName =
  | "init_run"
  | "design_eval"
  | "split_and_seal"
  | "build"
  | "dev_test"
  | "repair"
  | "freeze"
  | "evaluate"
  | "deliver";

export type CriterionMethod =
  | "exact_match"
  | "contains"
  | "schema_valid"
  | "numeric_tolerance"
  | "rubric";

export type VerdictStatus =
  | "ready"
  | "not_ready"
  | "insufficient"
  | "insufficient_evidence";

export interface HealthResponse {
  status: "ok";
  service: "adaptos-backend";
  version: string;
  sandbox_subprocess_fallback_enabled: boolean;
}

export interface ErrorRecord {
  stage: Stage;
  code: string;
  message: string;
  at?: string;
}

export interface AssetProfile {
  asset_id: string;
  filename: string;
  format: string;
  size_bytes: number;
  sha256: string;
}

export interface SourceAssetInput {
  asset_id: string;
  filename: string;
  content: string;
  format: string;
}

export interface FieldSpec {
  name: string;
  data_type:
    | "string"
    | "integer"
    | "number"
    | "boolean"
    | "object"
    | "array"
    | "file";
  description: string;
  required: boolean;
}

export interface AcceptanceCriterion {
  criterion_id: string;
  description: string;
  method: CriterionMethod;
  min_pass_rate: number;
}

export interface Spec {
  goal: string;
  inputs: FieldSpec[];
  outputs: FieldSpec[];
  constraints: string[];
  acceptance_criteria: AcceptanceCriterion[];
}

export interface ArtifactRef {
  version_id: string;
  artifact_hash: string;
}

export interface ArtifactFile {
  path: string;
  sha256: string;
  size_bytes: number;
}

export interface RuntimeLimits {
  wall_seconds: number;
  memory_mb: number;
}

export interface BundleManifest {
  version_id: string;
  parent_version_id: string | null;
  created_at: string;
  artifact_hash: string;
  spec_hash: string;
  architecture: "prompt_only" | "retrieval" | "tool_use";
  runtime_model: string;
  reasoning_effort?: "low" | "medium" | "high";
  entrypoint: string;
  files: ArtifactFile[];
  allowed_tools: string[];
  limits: RuntimeLimits;
}

export interface CriterionResult {
  criterion_id: string;
  method: CriterionMethod;
  threshold: number;
  n_passed: number;
  n_cases: number;
  pass_rate: number;
  wilson_lower: number;
  wilson_upper: number;
  status: "met" | "not_met" | "undetermined";
  passed: boolean;
}

export interface Verdict {
  verdict_id: string;
  spec_hash: string;
  artifact: ArtifactRef;
  sealed_set_id: string;
  sealed_commitment_hash: string;
  status: VerdictStatus;
  criteria: CriterionResult[];
  evidence_hash: string;
  issued_at: string;
  signing_key_id: string;
  signature: string;
  judge_model?: string | null;
}

export interface RepairRecord {
  attempt: number;
  parent_version_id: string;
  new_version_id: string;
  target_component: string;
  accepted: boolean;
  reason: string;
}

export interface DeliveryPackage {
  spec: Spec;
  artifact: BundleManifest;
  verdict: Verdict;
  repair_log: RepairRecord[];
  delivered_at: string;
}

export interface DevCaseResult {
  case_id: string;
  passed: boolean;
  score: number;
  failure_note: string;
}

export interface DevRun {
  version_id: string;
  pass_rate: number;
  results: DevCaseResult[];
}

export interface DevCase {
  case_id: string;
  input_data: Record<string, unknown>;
  expected_output: Record<string, unknown> | string;
  criterion_ids: string[];
}

export interface SealedSetCommitmentPublic {
  set_id: string;
  spec_hash: string;
  case_count: number;
  criterion_case_counts: Record<string, number>;
  commitment_hash: string;
  sealed_at: string;
}

export interface VerificationSnapshotExtension {
  spec?: Spec | null;
  sealed_commitment?: SealedSetCommitmentPublic | null;
  baseline_manifest?: BundleManifest | null;
  candidate_manifest?: BundleManifest | null;
  dev_cases?: DevCase[];
  dev_runs?: DevRun[];
  repair_log?: RepairRecord[];
}

export interface ProjectRunSummary {
  run_id: string;
  stage: Stage;
  user_goal: string;
  approved_spec_hash: string | null;
  plan_hash: string | null;
  sealed_set_id: string | null;
  baseline_version_id: string | null;
  candidate_version_id: string | null;
  frozen_version_id: string | null;
  dev_pass_rate: number | null;
  dev_test_passed: boolean;
  repair_attempts: number;
  repair_budget_left: number;
  verdict_status: VerdictStatus | null;
  verdict_id: string | null;
  is_ready_for_delivery: boolean;
  delivery_blob_sha256: string | null;
  errors: ErrorRecord[];
  events: string[];
  verification_snapshot?: VerificationSnapshotExtension | null;
}

export interface AuthorizedDownloadJsonResponse {
  run_id: string;
  version_id: string;
  artifact_hash: string;
  verdict_id: string;
  verdict_status: "ready";
  delivery_package: DeliveryPackage;
  files: Record<string, string>;
}

// ===========================================================================
// 1. VERIFIED 12-COMPONENT ARCHITECTURE REGISTRY (Source of Truth)
// ===========================================================================

export type ArchitectureComponentId =
  | "api_layer"
  | "adaptos_service"
  | "intake_profiling"
  | "spec_handoff"
  | "eval_design"
  | "split_and_seal"
  | "build_engine"
  | "sandbox_dev_test"
  | "repair_regression"
  | "protected_eval"
  | "verdict_delivery"
  | "storage_artifacts";

export type ImplementationStatus =
  | "Implemented"
  | "Implemented (Merged in service.py)"
  | "Implemented (Optional Judge Port)";

export interface ArchitectureNodeSpec {
  id: ArchitectureComponentId;
  index: number;
  title: string;
  shortLabel: string;
  zone:
    | "Entry & Facade"
    | "Specification & Split"
    | "Factory Execution Plane"
    | "Protected Evaluation Plane"
    | "Persistence Layer";
  sourceFiles: string[];
  status: ImplementationStatus;
  responsibility: string;
  classesAndFunctions: string[];
  inputs: string[];
  outputs: string[];
  dependencies: ArchitectureComponentId[];
  securityAndStorageNotes: string;
  x: number;
  y: number;
}

export interface ArchitectureEdgeSpec {
  from: ArchitectureComponentId;
  to: ArchitectureComponentId;
  label: string;
  category: "control" | "data" | "security" | "storage";
}

export const ARCHITECTURE_NODES: ArchitectureNodeSpec[] = [
  {
    id: "api_layer",
    index: 1,
    title: "API Layer",
    shortLabel: "01. API Layer",
    zone: "Entry & Facade",
    sourceFiles: ["backend/api.py"],
    status: "Implemented",
    responsibility:
      "FastAPI HTTP transport interface over AdaptOSService. Enforces constant-time Bearer API-key authentication (hmac.compare_digest), CORS allowlisting, lifespan singleton service initialization, and ready-gated ZIP/JSON downloads.",
    classesAndFunctions: [
      "create_app()",
      "verify_api_key()",
      "build_service_config_from_env()",
      "load_cors_origins_from_env()",
      "CreateProjectRequest / IngestAssetsRequest / SubmitSpecRequest / ApproveHandoffRequest",
      "AuthorizedDownloadJsonResponse",
    ],
    inputs: [
      "HTTP Requests with Authorization: Bearer <ADAPTOS_API_KEY>",
      "JSON payloads (CreateProjectRequest, SourceAssetInput[], Spec, HandoffPackage)",
    ],
    outputs: [
      "ProjectRunSummary JSON",
      "DeliveryPackage JSON",
      "Ready-gated application bundle ZIP / JSON download (HTTP 200 or HTTP 403)",
    ],
    dependencies: ["adaptos_service", "spec_handoff"],
    securityAndStorageNotes:
      "Never touches SQLite databases or evaluator vaults directly. Startup fails closed if ADAPTOS_EVAL_SERVICE_TOKEN or ADAPTOS_EVAL_SIGNING_SEED is missing.",
    x: 60,
    y: 70,
  },
  {
    id: "adaptos_service",
    index: 2,
    title: "AdaptOS Service & Orchestrator",
    shortLabel: "02. AdaptOS Service",
    zone: "Entry & Facade",
    sourceFiles: ["backend/service.py", "backend/graph.py"],
    status: "Implemented",
    responsibility:
      "Coordinates the 12-step AdaptOS lifecycle, serializes concurrent pipeline runs via asyncio.Lock, enforces duplicate run_id protection, and drives the 9-node LangGraph FactoryOrchestrator state machine.",
    classesAndFunctions: [
      "AdaptOSService",
      "AdaptOSServiceConfig",
      "FactoryOrchestrator (init_run -> design_eval -> split_and_seal -> build -> dev_test -> repair -> freeze -> evaluate -> deliver / fail)",
      "AuthenticatedEvaluatorServiceBridge",
      "ProjectRunSummary",
    ],
    inputs: [
      "user_goal: str, run_id: str | None",
      "SourceAssetInput[], Spec, HandoffPackage",
    ],
    outputs: [
      "FactoryGraphState ({factory, refs, events}) persisted in service_project_runs",
      "ProjectRunSummary (strictly separating dev_pass_rate from verdict_status)",
    ],
    dependencies: [
      "intake_profiling",
      "spec_handoff",
      "eval_design",
      "split_and_seal",
      "build_engine",
      "sandbox_dev_test",
      "repair_regression",
      "protected_eval",
      "verdict_delivery",
      "storage_artifacts",
    ],
    securityAndStorageNotes:
      "Fails closed in _load_active_run_assets() if any referenced asset blob cannot be loaded or validated. Post-freeze graph topology has zero backward edges to build, dev_test, or repair.",
    x: 340,
    y: 70,
  },
  {
    id: "intake_profiling",
    index: 3,
    title: "Intake & Asset Profiling",
    shortLabel: "03. Intake & Assets",
    zone: "Specification & Split",
    sourceFiles: ["backend/agent/intake.py", "backend/service.py"],
    status: "Implemented",
    responsibility:
      "Profiles uploaded user documents (txt, md, csv, json), rejects binary/null-byte content, computes SHA-256 digests, and verifies that proposed input/output fields are grounded in user transcript turns or uploaded asset chunks.",
    classesAndFunctions: [
      "AdaptOSService.ingest_assets()",
      "ProvenanceVerifier.verify_field_grounding()",
      "IntakeAssetProfile / AssetProfile",
      "TranscriptTurn / DiscoveryContext / RequirementRecord",
      "SqliteSerdeSaver",
    ],
    inputs: [
      "SourceAssetInput[]",
      "TranscriptTurn[]",
      "User goal & requirements",
    ],
    outputs: [
      "AssetProfile[] with SHA-256 & size_bytes",
      "Content-addressed raw_assets_blob_sha256 & assets_blob_sha256",
    ],
    dependencies: ["storage_artifacts", "spec_handoff"],
    securityAndStorageNotes:
      "Prevents hallucinated or ungrounded schema fields by requiring character-offset or quote-level grounding via ProvenanceVerifier.",
    x: 60,
    y: 230,
  },
  {
    id: "spec_handoff",
    index: 4,
    title: "Specification & Handoff",
    shortLabel: "04. Spec & Handoff",
    zone: "Specification & Split",
    sourceFiles: [
      "backend/schemas.py",
      "backend/agent/intake.py",
      "backend/service.py",
    ],
    status: "Implemented",
    responsibility:
      "Validates the canonical Spec contract, verifies in:<field> and out:<field> GroundedFieldSpec entries, checks CriterionProvenanceRecord requirement bindings, verifies ApprovalRecord.spec_sha256, and transitions FactoryState to eval_design.",
    classesAndFunctions: [
      "Spec / FieldSpec / AcceptanceCriterion",
      "HandoffPackage / ApprovalRecord / GroundedFieldSpec / CriterionProvenanceRecord",
      "apply_handoff_to_factory_state()",
      "_verify_handoff_provenance_and_hashes()",
    ],
    inputs: [
      "Submitted Spec",
      "Complete HandoffPackage with provenance_audit: dict[str, int]",
    ],
    outputs: [
      "Approved FactoryState (approved_spec_hash = spec.content_hash())",
      "Persisted handoff_blob_sha256",
    ],
    dependencies: ["storage_artifacts"],
    securityAndStorageNotes:
      "Spec is frozen upon approval; every downstream artifact (TestPlan, SealedSetCommitment, BundleManifest, Verdict) cryptographically chains to approved_spec_hash.",
    x: 340,
    y: 230,
  },
  {
    id: "eval_design",
    index: 5,
    title: "Evaluation Design",
    shortLabel: "05. Eval Designer",
    zone: "Specification & Split",
    sourceFiles: ["backend/eval_designer.py", "backend/graph.py"],
    status: "Implemented",
    responsibility:
      "Generates the undivided evaluation test pool from the approved Spec and source documents, checks statistical sizing per criterion (required_cases(threshold) for Wilson 95% confidence + dev cases), and enforces Role-based access control.",
    classesAndFunctions: [
      "EvalDesignerService.design_evaluation()",
      "ApprovedSpec.from_factory_spec()",
      "TestPlan / GeneratedTestCase / DeterministicReference",
      "AccessControlGuard / Role.SPLIT_CASES",
      "RealEvalDesignerAdapter",
    ],
    inputs: [
      "ApprovedSpec (bound to expected_spec_hash)",
      "SourceDocument[]",
    ],
    outputs: [
      "Undivided TestPlan persisted by plan_hash",
      "all_criteria_split_ready boolean gate",
    ],
    dependencies: ["spec_handoff"],
    securityAndStorageNotes:
      "Undivided TestPlan can only be read by a principal holding Role.SPLIT_CASES. If all_criteria_split_ready is False, FactoryOrchestrator routes immediately to fail.",
    x: 620,
    y: 70,
  },
  {
    id: "split_and_seal",
    index: 6,
    title: "Data Split & Sealing",
    shortLabel: "06. Split & Seal",
    zone: "Specification & Split",
    sourceFiles: [
      "backend/service.py",
      "backend/eval_plane/evaluator.py",
      "backend/graph.py",
    ],
    status: "Implemented (Merged in service.py)",
    responsibility:
      "Fetches the undivided TestPlan with Role.SPLIT_CASES, deterministically partitions dev cases vs. held-out cases, normalizes held-out cases into SealedEvaluationCase with explicit target_fields and full-case SHA-256 hashes, and seals them into SQLiteVaultAdapter.",
    classesAndFunctions: [
      "NormalizedVaultSplitterAdapter.split_and_seal()",
      "SealedEvaluationCase / compute_sealed_case_hash()",
      "SQLiteVaultAdapter.seal_normalized_cases()",
      "SealedSetCommitment",
    ],
    inputs: ["plan_hash", "Spec", "split_seed (42)"],
    outputs: [
      "DevCase[] blob (dev_cases_blob_sha256) for Builder/Repair",
      "SealedSetCommitment (set_id, commitment_hash) on FactoryState",
      "Normalized held-out cases sealed in eval_plane/vault.db",
    ],
    dependencies: ["eval_design", "storage_artifacts", "protected_eval"],
    securityAndStorageNotes:
      "Held-out cases are written directly to eval_plane/vault.db and never enter FactoryGraphState, Builder, or Repair. Full normalized case fields are bound into input_signature_hash and commitment_hash.",
    x: 620,
    y: 230,
  },
  {
    id: "build_engine",
    index: 7,
    title: "Build Engine",
    shortLabel: "07. Build Engine",
    zone: "Factory Execution Plane",
    sourceFiles: ["backend/agent/builder.py"],
    status: "Implemented",
    responsibility:
      "Executes the 8-stage build pipeline (B1 BuildGate -> B2 RequirementAnalyzer -> B3 RegistryClient -> B4 StrategyPlanner -> B5 PlanValidator -> B6 CodeGenOrchestrator -> B7 Assembler -> B8 BuildChecks) to produce sealed baseline and candidate bundles.",
    classesAndFunctions: [
      "BuildEngine.build_application()",
      "RequirementAnalyzer / RegistryClient / StrategyPlanner / PlanValidator",
      "CodeGenOrchestrator",
      "Assembler.assemble_and_seal_bundle() / load_bundle()",
      "BuildChecks.verify_bundle()",
    ],
    inputs: ["Deep copy of FactoryState", "DevCase[]", "SourceAssetInput[]"],
    outputs: [
      "Sealed baseline BundleManifest (v1.0.0-baseline)",
      "Sealed candidate BundleManifest (v1.0.0-candidate)",
    ],
    dependencies: ["spec_handoff", "sandbox_dev_test", "storage_artifacts"],
    securityAndStorageNotes:
      "Receives a deep copy of FactoryState so failed builds cannot corrupt orchestrator state. Generated fn.<id> code must pass 6-stage SandboxVerifier before assembly.",
    x: 60,
    y: 390,
  },
  {
    id: "sandbox_dev_test",
    index: 8,
    title: "Sandbox & Development Testing",
    shortLabel: "08. Sandbox & Runtime",
    zone: "Factory Execution Plane",
    sourceFiles: ["backend/sandbox.py", "backend/runtime.py"],
    status: "Implemented",
    responsibility:
      "Leaf AST/signature linter and isolated Docker sandbox worker (sandbox.py) paired with the fixed schema-driven bundle interpreter, ContextEngineeringEngine, and deterministic DevTestRunner (runtime.py).",
    classesAndFunctions: [
      "SandboxVerifier.lint_ast_and_signature() / execute_in_sandbox() / verify_generated_component()",
      "AppRuntime.verify_bundle_integrity() / execute_bundle() / _resolve_step_inputs()",
      "ContextEngineeringEngine.compose_context()",
      "DevTestRunner.run_dev_suite() / _grade_dev_case()",
    ],
    inputs: [
      "BundleManifest & files_data: dict[str, bytes]",
      "DevCase[] & SourceAssetInput[]",
    ],
    outputs: [
      "DevRun (version_id, pass_rate, DevCaseResult[])",
      "CaseExecutionTrace (StepTrace[] per step)",
      "ValidationReport (6-stage component verification)",
    ],
    dependencies: ["storage_artifacts"],
    securityAndStorageNotes:
      "Enforces artifact SHA-256 & byte-length integrity, step input_map dataflow isolation, RuntimeLimits (wall_seconds, memory_mb), allowed_tools authorization, and Docker --network none --read-only isolation.",
    x: 340,
    y: 390,
  },
  {
    id: "repair_regression",
    index: 9,
    title: "Repair & Regression Gate",
    shortLabel: "09. Repair Agent",
    zone: "Factory Execution Plane",
    sourceFiles: ["backend/agent/repair.py"],
    status: "Implemented",
    responsibility:
      "Reproduces dev failures (<=8 cases), performs deterministic criteria_map triage, proposes bounded patches (config, prompt, swap, code), validates RFC 6901 JSON Pointers & literal-leak guards, stages immutable child bundles in memory, enforces a strict failing-first RegressionGate, and persists transactionally.",
    classesAndFunctions: [
      "repair_attempt()",
      "EvidenceCollector / FailureTriage / RepairProposer",
      "PatchValidator / parse_json_pointer() / apply_config_pointer()",
      "PatchApplier.stage_child_bundle() / verify_staged_bundle() / persist_verified_bundle()",
      "RegressionGate.verify_and_decide()",
      "RepairLedgerStore / AttemptReportBuilder",
    ],
    inputs: [
      "BundleRepairRequest (candidate_manifest, latest_dev_run, budget_left, tried_patch_hashes)",
    ],
    outputs: [
      "BundleRepairOutcome (repaired | rejected | no_failure | aborted)",
      "RepairRecord & content-addressed AttemptReport blob",
      "Child BundleManifest (v1.0.0-candidate-r1..r3)",
    ],
    dependencies: ["sandbox_dev_test", "storage_artifacts"],
    securityAndStorageNotes:
      "Hard cap of 3 repair attempts enforced at graph level. Guard components (io.validate, cite.verify, log.trace), schemas/**, and platform *.py files are read-only. Flaky retries are rejected as inconclusive.",
    x: 620,
    y: 390,
  },
  {
    id: "protected_eval",
    index: 10,
    title: "Protected Evaluation Plane",
    shortLabel: "10. Protected Evaluator",
    zone: "Protected Evaluation Plane",
    sourceFiles: ["backend/eval_plane/evaluator.py", "backend/service.py"],
    status: "Implemented (Optional Judge Port)",
    responsibility:
      "Executes frozen bundles against sealed held-out cases in per-attempt fenced scratch storage with a single absolute per-case wall_seconds deadline. Performs strict target_fields grading, records private evidence, computes Wilson 95% intervals, and signs Verdict with Ed25519.",
    classesAndFunctions: [
      "EvaluatorCoordinator.evaluate_job() (Steps S1-S12)",
      "BootGuard / SubmissionVerifier / SealedSetReader / ArtifactLoader",
      "EnvironmentFactory / AttemptExecutionFence / _FencedAttemptStorage",
      "CaseExecutor / CaseGrader / Aggregator",
      "VerdictBuilderAndSigner / EvidenceRecorder / EvaluationLedger / RedactionLayer",
    ],
    inputs: [
      "Authenticated EvaluationJob (EvaluationRequest, Spec, BundleManifest, files_data, SourceAssetInput[])",
    ],
    outputs: [
      "EvaluationOutcome containing Ed25519-signed Verdict OR typed AbortCode",
    ],
    dependencies: ["split_and_seal", "sandbox_dev_test"],
    securityAndStorageNotes:
      "BootGuard enforces AGNOS_PROCESS_ROLE=eval and blocks factory credentials. One-shot atomic budget reservation per (sealed_set_id, artifact). Held-out inputs/outputs never leave evaluator.py.",
    x: 900,
    y: 230,
  },
  {
    id: "verdict_delivery",
    index: 11,
    title: "Verdict & Delivery Authorization",
    shortLabel: "11. Verdict & Delivery",
    zone: "Protected Evaluation Plane",
    sourceFiles: [
      "backend/service.py",
      "backend/graph.py",
      "backend/schemas.py",
    ],
    status: "Implemented",
    responsibility:
      "Verifies Ed25519 signature over Verdict.signing_payload() using only the factory's public key, verifies hash bindings (spec_hash, artifact_hash, sealed_commitment_hash), packages DeliveryPackage, and blocks artifact file downloads unless Verdict.status == 'ready'.",
    classesAndFunctions: [
      "Ed25519Signer.verify_signature()",
      "VerifiedDeliveryAdapter.verify_verdict_authenticity() / deliver()",
      "AdaptOSService.get_delivery_package() / get_authorized_delivery()",
      "Verdict / CriterionResult / DeliveryPackage",
    ],
    inputs: ["Frozen BundleManifest", "Signed Verdict", "RepairRecord[]"],
    outputs: [
      "DeliveryPackage blob (delivery_blob_sha256)",
      "Authorized bundle files (ZIP / JSON) if and only if Verdict.status === 'ready'",
    ],
    dependencies: ["protected_eval", "storage_artifacts"],
    securityAndStorageNotes:
      "Development test pass rates (DevRun) can never authorize delivery. A 'not_ready' Verdict produces an honest DeliveryPackage record but raises DeliveryNotAuthorizedError (HTTP 403) on download.",
    x: 900,
    y: 390,
  },
  {
    id: "storage_artifacts",
    index: 12,
    title: "Storage & Artifact Management",
    shortLabel: "12. Storage & Blobs",
    zone: "Persistence Layer",
    sourceFiles: ["backend/storage.py", "backend/eval_plane/evaluator.py"],
    status: "Implemented",
    responsibility:
      "Content-addressed SHA-256 blob store, factory SQLite database (builder_bundles, builder_component_registry, repair_attempts_ledger, service_project_runs), tenant-scoped FTS5 lexical indexes, LangGraph checkpoint DB, and isolated eval_plane/vault.db + eval_ledger.db.",
    classesAndFunctions: [
      "StorageService (put_blob, get_blob, verify_blob, get_factory_db, provision_app_storage, add_fts5_document, search_fts5)",
      "StorageAssetStoreAdapter",
      "SQLiteVaultAdapter (eval_plane/vault.db)",
      "EvaluationLedger & EvidenceRecorder (eval_plane/eval_ledger.db)",
    ],
    inputs: ["Canonical JSON / raw file bytes", "SQLite transactions"],
    outputs: [
      "Verified SHA-256 digests",
      "Tenant-isolated FTS5 search hits",
    ],
    dependencies: [],
    securityAndStorageNotes:
      "Strict physical separation between factory_storage (blobs, factory.db, checkpoints.db) and eval_plane (vault.db, eval_ledger.db). Evaluator never reads factory storage.",
    x: 900,
    y: 70,
  },
];

export const ARCHITECTURE_EDGES: ArchitectureEdgeSpec[] = [
  {
    from: "api_layer",
    to: "adaptos_service",
    label: "Bearer Auth + DTOs",
    category: "control",
  },
  {
    from: "adaptos_service",
    to: "intake_profiling",
    label: "ingest_assets()",
    category: "data",
  },
  {
    from: "intake_profiling",
    to: "spec_handoff",
    label: "GroundedFieldSpec + Quotes",
    category: "security",
  },
  {
    from: "adaptos_service",
    to: "spec_handoff",
    label: "submit_spec / approve_spec",
    category: "control",
  },
  {
    from: "spec_handoff",
    to: "eval_design",
    label: "ApprovedSpec (spec_hash)",
    category: "data",
  },
  {
    from: "eval_design",
    to: "split_and_seal",
    label: "Undivided TestPlan (Role.SPLIT_CASES)",
    category: "security",
  },
  {
    from: "split_and_seal",
    to: "build_engine",
    label: "DevCase[] Blob",
    category: "data",
  },
  {
    from: "split_and_seal",
    to: "protected_eval",
    label: "SealedEvaluationCase[] -> vault.db",
    category: "security",
  },
  {
    from: "build_engine",
    to: "sandbox_dev_test",
    label: "Verify fn.py + Dry-Run",
    category: "control",
  },
  {
    from: "sandbox_dev_test",
    to: "repair_regression",
    label: "Failing DevRun + StepTraces",
    category: "data",
  },
  {
    from: "repair_regression",
    to: "sandbox_dev_test",
    label: "Staged Child + RegressionGate",
    category: "control",
  },
  {
    from: "adaptos_service",
    to: "protected_eval",
    label: "Service-Token EvaluationJob",
    category: "security",
  },
  {
    from: "protected_eval",
    to: "verdict_delivery",
    label: "Ed25519 Signed Verdict",
    category: "security",
  },
  {
    from: "verdict_delivery",
    to: "api_layer",
    label: "Ready-Gated ZIP / 403 Deny",
    category: "security",
  },
  {
    from: "adaptos_service",
    to: "storage_artifacts",
    label: "Checkpoints & Blobs",
    category: "storage",
  },
];

// ===========================================================================
// 2. WORKFLOW PIPELINE STAGES (graph.py FactoryOrchestrator)
// ===========================================================================

export interface WorkflowNodeMetadata {
  node: StageNodeName;
  label: string;
  orchestratorMethod: string;
  underlyingCall: string;
  routingRule: string;
  description: string;
}

export const WORKFLOW_STAGES: WorkflowNodeMetadata[] = [
  {
    node: "init_run",
    label: "1. init_run",
    orchestratorMethod: "FactoryOrchestrator.init_run_node",
    underlyingCall:
      "apply_handoff_to_factory_state() + _verify_spec_hash_chain()",
    routingRule: "On success -> design_eval | On error -> fail",
    description:
      "Loads approved HandoffPackage and source assets blob, clamps max_repair_attempts <= 3, and verifies the Spec SHA-256 chain.",
  },
  {
    node: "design_eval",
    label: "2. design_eval",
    orchestratorMethod: "FactoryOrchestrator.design_eval_node",
    underlyingCall:
      "ApprovedSpec.from_factory_spec() -> EvalDesignerService.design_evaluation()",
    routingRule:
      "all_criteria_split_ready == True -> split_and_seal | Else -> fail",
    description:
      "Designs criterion-aligned evaluation test cases and verifies statistical coverage requirements before splitting.",
  },
  {
    node: "split_and_seal",
    label: "3. split_and_seal",
    orchestratorMethod: "FactoryOrchestrator.split_and_seal_node",
    underlyingCall:
      "NormalizedVaultSplitterAdapter.split_and_seal() -> SQLiteVaultAdapter.seal_normalized_cases()",
    routingRule: "sealed != None -> build | Else -> fail",
    description:
      "Splits TestPlan into DevCase[] blob for Builder/Repair and seals normalized held-out cases into eval_plane/vault.db with a SealedSetCommitment.",
  },
  {
    node: "build",
    label: "4. build",
    orchestratorMethod: "FactoryOrchestrator.build_node",
    underlyingCall:
      "BuildEngine.build_application(state.model_copy(deep=True), dev_cases, assets)",
    routingRule: "status == 'built' -> dev_test | unsupported/failed -> fail",
    description:
      "Plans, validates, generates sandbox-verified tools if needed, and seals both v1.0.0-baseline and v1.0.0-candidate bundles.",
  },
  {
    node: "dev_test",
    label: "5. dev_test",
    orchestratorMethod: "FactoryOrchestrator.dev_test_node",
    underlyingCall:
      "DevTestRunner.run_dev_suite(baseline) + DevTestRunner.run_dev_suite(candidate)",
    routingRule:
      "baseline or candidate 100% pass -> freeze | Both fail & budget > 0 -> repair",
    description:
      "Runs deterministic development test cases against both baseline and candidate bundles using AppRuntime.",
  },
  {
    node: "repair",
    label: "6. repair",
    orchestratorMethod: "FactoryOrchestrator.repair_node",
    underlyingCall:
      "repair_attempt(BundleRepairRequest) + _validate_repair_outcome()",
    routingRule:
      "stage == 'frozen' -> evaluate | budget_left > 0 -> repair (max 3 attempts) | error -> fail",
    description:
      "Executes one checkpointed bounded repair attempt per node invocation, validating parent-child version chaining and RegressionGate results.",
  },
  {
    node: "freeze",
    label: "7. freeze",
    orchestratorMethod: "FactoryOrchestrator.freeze_node",
    underlyingCall:
      "_select_best_eligible_manifest() -> state.frozen = chosen.ref",
    routingRule:
      "frozen != None -> evaluate | Else -> fail (Zero backward edges after freeze)",
    description:
      "Selects the simplest passing bundle (baseline if passing, else last_passing or best candidate) and permanently freezes its ArtifactRef.",
  },
  {
    node: "evaluate",
    label: "8. evaluate",
    orchestratorMethod: "FactoryOrchestrator.evaluate_node",
    underlyingCall:
      "AuthenticatedEvaluatorServiceBridge.evaluate() -> EvaluatorCoordinator.evaluate_job()",
    routingRule:
      "Ed25519 signature & hash bindings verified -> deliver | Abort/mismatch -> fail",
    description:
      "Submits the frozen bundle over the authenticated bridge to the Protected Evaluation Plane and verifies the returned Ed25519-signed Verdict.",
  },
  {
    node: "deliver",
    label: "9. deliver",
    orchestratorMethod: "FactoryOrchestrator.deliver_node",
    underlyingCall: "VerifiedDeliveryAdapter.deliver() -> DeliveryPackage blob",
    routingRule:
      "Package stored -> END (Download gated on Verdict.status == 'ready')",
    description:
      "Seals the final DeliveryPackage (spec, frozen manifest, signed Verdict, repair_log). Artifact download is permitted only if Verdict is 'ready'.",
  },
];

// ===========================================================================
// 3. 10-STEP JUDGE DEMO MODE WALKTHROUGH
// ===========================================================================

export interface DemoStepSpec {
  stepNumber: number;
  title: string;
  subtitle: string;
  targetTab: "architecture" | "workflow" | "verification";
  focusComponentId?: ArchitectureComponentId;
  focusWorkflowNode?: StageNodeName;
  focusVerificationLayer?:
    | "A_dev"
    | "B_criteria"
    | "C_repair"
    | "D_eval"
    | "E_artifact";
  narrative: string;
  codeEvidenceRef: string;
  keyTakeaway: string;
}

export const DEMO_STEPS: DemoStepSpec[] = [
  {
    stepNumber: 1,
    title: "AdaptOS Architecture & Trust Boundaries",
    subtitle:
      "Strict separation between the Untrusted Factory Plane and Protected Evaluation Plane",
    targetTab: "architecture",
    focusComponentId: "adaptos_service",
    narrative:
      "AdaptOS is engineered around a verifiable trust boundary: the Factory Plane (Intake, Builder, Runtime, Repair) never sees held-out test cases or the Ed25519 private signing key. All 12 modules communicate through hash-bound Pydantic contracts.",
    codeEvidenceRef:
      "backend/service.py • backend/graph.py • backend/schemas.py",
    keyTakeaway:
      "No component can self-certify readiness; only the isolated Protected Evaluation Plane can issue a signed Verdict.",
  },
  {
    stepNumber: 2,
    title: "Objective Intake & Source Asset Profiling",
    subtitle: "Content-addressed asset ingestion and quote-level field grounding",
    targetTab: "architecture",
    focusComponentId: "intake_profiling",
    narrative:
      "When a user creates a project and uploads policy documents (md, txt, csv, json), AdaptOSService.ingest_assets() rejects empty/binary payloads, computes SHA-256 digests, and stores content-addressed blobs. Every proposed I/O field must be grounded in user transcript quotes or asset chunks via ProvenanceVerifier.verify_field_grounding().",
    codeEvidenceRef:
      "backend/agent/intake.py • AdaptOSService.ingest_assets()",
    keyTakeaway:
      "Prevents hallucinated requirements before a single line of application config or code is built.",
  },
  {
    stepNumber: 3,
    title: "Specification Approval & Handoff Verification",
    subtitle: "Cryptographic Spec hash chaining and provenance audit",
    targetTab: "verification",
    focusVerificationLayer: "B_criteria",
    narrative:
      "AdaptOSService.approve_spec() validates the complete HandoffPackage: every Spec input has an 'in:<name>' GroundedFieldSpec, every output has an 'out:<name>' GroundedFieldSpec, every acceptance criterion maps to an active RequirementRecord, and ApprovalRecord.spec_sha256 locks the Spec content hash.",
    codeEvidenceRef:
      "backend/service.py:_verify_handoff_provenance_and_hashes()",
    keyTakeaway:
      "Once approved, approved_spec_hash is immutable across TestPlan, SealedSetCommitment, BundleManifest, and Verdict.",
  },
  {
    stepNumber: 4,
    title: "Evaluation Design, Splitting & Vault Sealing",
    subtitle:
      "Wilson 95% sample sizing and full-case cryptographic commitment",
    targetTab: "architecture",
    focusComponentId: "split_and_seal",
    narrative:
      "EvalDesignerService generates the undivided test pool and checks required_cases(threshold). NormalizedVaultSplitterAdapter (using Role.SPLIT_CASES) splits DevCase[] for Builder and seals held-out SealedEvaluationCase[] into eval_plane/vault.db, binding case_id, criterion_id, method, input_data, target_fields, and expected_output into commitment_hash.",
    codeEvidenceRef:
      "backend/eval_designer.py • backend/eval_plane/evaluator.py:compute_sealed_case_hash()",
    keyTakeaway:
      "Held-out cases never enter FactoryGraphState, checkpoints, logs, or prompts.",
  },
  {
    stepNumber: 5,
    title: "Build Engine & Isolated Docker Sandbox",
    subtitle:
      "8-stage bundle assembly, AST linting, and fail-closed container execution",
    targetTab: "architecture",
    focusComponentId: "sandbox_dev_test",
    narrative:
      "BuildEngine assembles both a minimal baseline control bundle and a candidate bundle. Any generated Python component (fn.<id>) must pass 6-stage SandboxVerifier checks (AST lint, signature check, secret scan, Docker --network none --read-only execution, double-run determinism, and hidden vector confidentiality).",
    codeEvidenceRef:
      "backend/agent/builder.py • backend/sandbox.py:SandboxVerifier",
    keyTakeaway:
      "AppRuntime.verify_bundle_integrity() verifies every file's size_bytes and SHA-256 before execution.",
  },
  {
    stepNumber: 6,
    title: "Development Testing (DevTestRunner)",
    subtitle:
      "Deterministic dev suite execution on baseline and candidate bundles",
    targetTab: "verification",
    focusVerificationLayer: "A_dev",
    narrative:
      "In the dev_test stage, DevTestRunner executes the dev subset against both v1.0.0-baseline and v1.0.0-candidate. Exact match performs strict typed equality (no substring false positives), and schema_valid checks the declared JSON Schema. Dev pass rates guide repair—but never authorize delivery.",
    codeEvidenceRef: "backend/runtime.py:DevTestRunner.run_dev_suite()",
    keyTakeaway:
      "Development testing is strictly separated from protected evaluation.",
  },
  {
    stepNumber: 7,
    title: "Bounded Self-Repair & Strict Regression Gate",
    subtitle:
      "At most 3 checkpointed repair attempts with atomic child bundle persistence",
    targetTab: "verification",
    focusVerificationLayer: "C_repair",
    narrative:
      "When dev_test fails (e.g., retrieve.lexical mode='all' returning 0 passages on natural-language ticket queries), Repair Agent reproduces the failure, triages suspect steps via criteria_map, validates the proposed patch (RFC 6901 JSON Pointer allowlist & literal-leak check), runs RegressionGate (rejecting flaky retries), and atomically seals v1.0.0-candidate-r1.",
    codeEvidenceRef:
      "backend/agent/repair.py:repair_attempt() & RegressionGate",
    keyTakeaway:
      "Child bundles are verified in-memory and persisted transactionally only after fixing targets with 0 regressions.",
  },
  {
    stepNumber: 8,
    title: "Protected Evaluation Plane (Steps S1–S12)",
    subtitle:
      "Per-case fenced storage, single absolute deadlines, and strict target_fields grading",
    targetTab: "verification",
    focusVerificationLayer: "D_eval",
    narrative:
      "After freeze, AuthenticatedEvaluatorServiceBridge submits an EvaluationJob to EvaluatorCoordinator. The evaluator verifies S1 hash bindings, reserves the one-shot sealed-set budget atomically in eval_ledger.db, executes each held-out case with a fresh _FencedAttemptStorage and single wall_seconds deadline, grades target_fields strictly, and records private evidence.",
    codeEvidenceRef:
      "backend/eval_plane/evaluator.py:EvaluatorCoordinator.evaluate_job()",
    keyTakeaway:
      "Infrastructure errors abort without producing a false not_ready verdict; timed-out threads are fenced from storage and API credits.",
  },
  {
    stepNumber: 9,
    title: "Wilson 95% Confidence Verdict & Ed25519 Signature",
    subtitle: "Mathematical readiness decision and cryptographic authenticity",
    targetTab: "verification",
    focusVerificationLayer: "D_eval",
    narrative:
      "For each acceptance criterion, CriterionResult.from_counts() computes the 95% Wilson score interval. 'met' requires wilson_lower >= threshold; 'not_met' means wilson_upper < threshold. VerdictBuilderAndSigner signs Verdict.signing_payload() with Ed25519 at Step S11 and self-verifies before returning.",
    codeEvidenceRef:
      "backend/schemas.py:CriterionResult.from_counts() • VerdictBuilderAndSigner",
    keyTakeaway:
      "Any 'not_met' criterion forces status='not_ready'; any 'undetermined' criterion forces 'insufficient_evidence'.",
  },
  {
    stepNumber: 10,
    title: "Ready-Gated Artifact Delivery Authorization",
    subtitle:
      "Cryptographic verification and HTTP 200 vs. HTTP 403 enforcement",
    targetTab: "verification",
    focusVerificationLayer: "E_artifact",
    narrative:
      "Finally, AdaptOSService.get_authorized_delivery() verifies the Ed25519 signature against eval_public_key_bytes, confirms Verdict.artifact matches the frozen BundleManifest hash, and re-runs AppRuntime.verify_bundle_integrity(). If Verdict.status is 'ready', the ZIP/JSON bundle is released; if 'not_ready', download is blocked with HTTP 403 Forbidden.",
    codeEvidenceRef:
      "backend/service.py:get_authorized_delivery() • backend/api.py:/download",
    keyTakeaway:
      "An unverified or failing application can never be downloaded as a deliverable artifact.",
  },
];

// ===========================================================================
// 4. HELPER: PARSE REPAIR RECORD REASON & BUILD GROUNDED HANDOFF PAYLOAD
// ===========================================================================

export interface ParsedRepairReason {
  reportSha256: string | null;
  costTag: string | null;
  summaryText: string;
}

export function parseRepairReason(reason: string): ParsedRepairReason {
  const match = reason.match(/^report=([a-f0-9]{64});\s*cost=([^;]+);\s*(.*)$/i);
  if (!match) {
    return { reportSha256: null, costTag: null, summaryText: reason };
  }
  return {
    reportSha256: match[1],
    costTag: match[2],
    summaryText: match[3],
  };
}

export const DEFAULT_DEMO_SPEC: Spec = {
  goal: "Triage customer refund requests against Section 4.2 Refund Policy and cite evidence.",
  inputs: [
    {
      name: "customer_query",
      data_type: "string",
      description: "Customer support request text.",
      required: true,
    },
    {
      name: "days_since_purchase",
      data_type: "integer",
      description: "Days elapsed since initial purchase.",
      required: true,
    },
  ],
  outputs: [
    {
      name: "decision",
      data_type: "string",
      description: "Triage decision label (approve_refund, reject_refund).",
      required: true,
    },
    {
      name: "policy_citation",
      data_type: "string",
      description: "Verbatim supporting policy citation.",
      required: true,
    },
  ],
  constraints: ["Never approve refunds after 30 calendar days."],
  acceptance_criteria: [
    {
      criterion_id: "crit_exact_decision",
      description:
        "Accurately classifies refund eligibility decision label.",
      method: "exact_match",
      min_pass_rate: 0.8,
    },
    {
      criterion_id: "crit_citation",
      description:
        "Includes policy citation from Section 4.2 Refund Policy.",
      method: "contains",
      min_pass_rate: 0.8,
    },
  ],
};

export const DEFAULT_DEMO_ASSET: SourceAssetInput = {
  asset_id: "pol_v1",
  filename: "refund_policy.md",
  content:
    "Section 4.2 Refund Policy: Full refunds are granted within 30 calendar days of purchase if the software license key has not been activated.",
  format: "md",
};

function canonicalizeValue(val: unknown): unknown {
  if (val === null || typeof val !== "object") {
    return val;
  }
  if (Array.isArray(val)) {
    return val.map(canonicalizeValue);
  }
  const obj = val as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const out: Record<string, unknown> = {};
  for (const k of sortedKeys) {
    out[k] = canonicalizeValue(obj[k]);
  }
  return out;
}

export async function sha256HexBrowser(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function computeSpecContentHash(spec: Spec): Promise<string> {
  const canonical = JSON.stringify(canonicalizeValue(spec));
  return sha256HexBrowser(canonical);
}

/**
 * Constructs a synthetic demo HandoffPackage payload aligned with the backend
 * intake.py Pydantic schemas:
 * - DiscoveryContext: operation_mode, existing_systems_context, available_data_context, success_criteria_context
 * - RequirementRecord: req_id, category, statement, active, provenance
 * - Provenance: kind, source_turn_id, source_quote, source_asset_id, source_chunk_id, start_char, end_char
 * - GroundedFieldSpec: name, data_type, description, required, source_turn_id, source_quote, source_asset_id, source_chunk_id, start_char, end_char
 * - CriterionProvenanceRecord: criterion_id, requirement_ids, rationale (no unsupported provenance field)
 * - TranscriptTurn: turn_id, role, text, timestamp (no content or at fields)
 * - Demo integrity: explicitly labeled as a built-in synthetic demo fixture with zero fabricated model/token/cost telemetry.
 */
export async function buildGroundedHandoffFromSpec(
  spec: Spec,
  specSha256?: string
): Promise<Record<string, unknown>> {
  const computedHash = specSha256 || (await computeSpecContentHash(spec));
  const nowIso = new Date().toISOString();
  const reqId = "req_001";
  const turnId = "turn_1";

  const fixtureHeader =
    "[BUILT-IN SYNTHETIC DEMO FIXTURE — Deterministic specification grounding text; not a live user conversation]";
  const goalQuote = `Requirement ${reqId}: ${spec.goal}`;
  const fieldQuotes: Record<string, string> = {};
  const quoteLines: string[] = [fixtureHeader, goalQuote];

  for (const f of [...spec.inputs, ...spec.outputs]) {
    const humanName = f.name.replace(/_/g, " ");
    const q = `Field ${f.name} (${humanName}, type ${f.data_type}): ${f.description}`;
    fieldQuotes[f.name] = q;
    quoteLines.push(q);
  }
  for (const c of spec.acceptance_criteria) {
    quoteLines.push(
      `Criterion ${c.criterion_id} (${c.method}): ${c.description}`
    );
  }

  const fullTranscriptText = quoteLines.join("\n");
  const goalStart = fullTranscriptText.indexOf(goalQuote);
  const goalEnd = goalStart + goalQuote.length;

  const fieldProvenance: Record<string, unknown> = {};
  for (const f of spec.inputs) {
    const q = fieldQuotes[f.name];
    const start = fullTranscriptText.indexOf(q);
    fieldProvenance[`in:${f.name}`] = {
      name: f.name,
      data_type: f.data_type,
      description: f.description,
      required: f.required,
      source_turn_id: turnId,
      source_quote: q,
      source_asset_id: null,
      source_chunk_id: null,
      start_char: start,
      end_char: start + q.length,
    };
  }
  for (const f of spec.outputs) {
    const q = fieldQuotes[f.name];
    const start = fullTranscriptText.indexOf(q);
    fieldProvenance[`out:${f.name}`] = {
      name: f.name,
      data_type: f.data_type,
      description: f.description,
      required: f.required,
      source_turn_id: turnId,
      source_quote: q,
      source_asset_id: null,
      source_chunk_id: null,
      start_char: start,
      end_char: start + q.length,
    };
  }

  const reqProvenance = {
  kind: "user_provided",
  turn_id: turnId,
  quote: goalQuote,
  source_asset_id: null,
  source_chunk_id: null,
  start_char: goalStart,
  end_char: goalEnd,
  };
  return {
    spec,
    spec_sha256: computedHash,
    approval: {
      by: "synthetic_demo_fixture",
      at: nowIso,
      revision: 1,
      spec_sha256: computedHash,
    },
    discovery_context: {
      operation_mode: "new_solution",
      existing_systems_context:
        "Built-in synthetic demo fixture: standalone policy triage workflow.",
      available_data_context:
        "Built-in synthetic demo fixture: Section 4.2 Refund Policy markdown asset.",
      success_criteria_context: `Built-in synthetic demo fixture: satisfy acceptance criteria for goal: ${spec.goal}`,
    },
    requirements: [
      {
        req_id: reqId,
        category: "functional",
        statement: spec.goal,
        active: true,
        provenance: reqProvenance,
      },
    ],
    field_provenance: fieldProvenance,
    criterion_provenance: spec.acceptance_criteria.map((c) => ({
      criterion_id: c.criterion_id,
      requirement_ids: [reqId],
      rationale: `[Built-in synthetic demo fixture] ${c.description}`,
    })),
    transcript: [
      {
        turn_id: turnId,
        role: "user",
        text: fullTranscriptText,
        timestamp: nowIso,
      },
    ],
    asset_manifest: [],
    provenance_audit: {
      user_provided: 1,
      asset_derived: 0,
      inferred: 0,
      invented_fields_rejected: 0,
    },
    agent1_run: {
      fixture_type: "built_in_synthetic_demo_fixture",
      model_executed: false,
    },
  };
}
