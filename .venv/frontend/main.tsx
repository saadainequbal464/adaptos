// frontend/src/main.tsx
// Entrypoint & Complete Monochrome Technical Design System for AdaptOS.

import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";

const ADAPTOS_STYLES = `
:root {
  --bg-black: #09090b;
  --bg-charcoal: #121215;
  --bg-elevated: #18181b;
  --border-subtle: #27272a;
  --border-strong: #3f3f46;
  --text-white: #fafafa;
  --text-silver: #a1a1aa;
  --text-muted: #71717a;
  --font-sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --font-mono: "JetBrains Mono", "Fira Code", "Cascadia Code", Consolas, monospace;
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  background-color: var(--bg-black);
  color: var(--text-white);
  font-family: var(--font-sans);
  font-size: 13px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

.mono {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
}

.adaptos-shell {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

/* TOP COMMAND BAR */
.adaptos-topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 24px;
  background: var(--bg-charcoal);
  border-bottom: 1px solid var(--border-subtle);
  gap: 16px;
  flex-wrap: wrap;
}

.brand-cluster {
  display: flex;
  align-items: center;
  gap: 12px;
}

.brand-mark {
  font-family: var(--font-mono);
  font-weight: 800;
  font-size: 15px;
  letter-spacing: 0.14em;
  padding: 4px 10px;
  background: var(--text-white);
  color: var(--bg-black);
}

.brand-divider {
  width: 1px;
  height: 18px;
  background: var(--border-strong);
}

.brand-subtitle {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-silver);
  letter-spacing: 0.06em;
}

.workspace-tabs {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}

.ws-tab {
  background: transparent;
  color: var(--text-silver);
  border: 1px solid var(--border-subtle);
  padding: 7px 14px;
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.05em;
  cursor: pointer;
  transition: all 0.15s ease;
}

.ws-tab:hover {
  color: var(--text-white);
  border-color: var(--border-strong);
}

.ws-tab.active {
  background: var(--text-white);
  color: var(--bg-black);
  border-color: var(--text-white);
}

.ws-tab.demo-highlight {
  border-color: var(--text-silver);
}

.status-cluster {
  display: flex;
  align-items: center;
  gap: 10px;
}

.health-pill {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-family: var(--font-mono);
  font-size: 11px;
  padding: 5px 10px;
  border: 1px solid var(--border-subtle);
  background: var(--bg-elevated);
}

.health-pill .dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--text-muted);
}

.health-pill.online .dot {
  background: var(--text-white);
  box-shadow: 0 0 6px var(--text-white);
}

/* PROJECT CONTEXT BAR */
.project-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 24px;
  background: var(--bg-black);
  border-bottom: 1px solid var(--border-subtle);
  gap: 16px;
  flex-wrap: wrap;
}

.project-selector {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.mono-label {
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.08em;
  color: var(--text-silver);
  text-transform: uppercase;
  margin-bottom: 4px;
  display: block;
}

.mono-input {
  background: var(--bg-charcoal);
  border: 1px solid var(--border-strong);
  color: var(--text-white);
  font-family: var(--font-mono);
  font-size: 12px;
  padding: 6px 10px;
  min-width: 190px;
}

.btn-primary,
.btn-secondary,
.btn-ghost {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  padding: 7px 12px;
  cursor: pointer;
  border: 1px solid var(--border-strong);
  transition: all 0.12s ease;
}

.btn-primary {
  background: var(--text-white);
  color: var(--bg-black);
  border-color: var(--text-white);
}

.btn-primary:hover:not(:disabled) {
  background: #e4e4e7;
}

.btn-secondary {
  background: var(--bg-elevated);
  color: var(--text-white);
}

.btn-secondary:hover:not(:disabled) {
  border-color: var(--text-white);
}

.btn-ghost {
  background: transparent;
  color: var(--text-silver);
  border-color: var(--border-subtle);
}

button:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

.poll-toggle {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-silver);
  margin-left: 6px;
  cursor: pointer;
}

.project-kpis {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.kpi-chip {
  background: var(--bg-charcoal);
  border: 1px solid var(--border-subtle);
  padding: 5px 12px;
  display: flex;
  flex-direction: column;
}

.kpi-chip.verdict-ready {
  border-color: var(--text-white);
  background: #18181b;
}

.kpi-chip.verdict-not-ready {
  border-style: dashed;
}

.kpi-label {
  font-family: var(--font-mono);
  font-size: 9px;
  color: var(--text-muted);
  letter-spacing: 0.08em;
}

.kpi-val {
  font-size: 12px;
  font-weight: 700;
  color: var(--text-white);
}

/* AUTH DRAWER & ACTION BANNER */
.auth-drawer {
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border-strong);
  padding: 16px 24px;
}

.auth-drawer-inner {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  gap: 24px;
  flex-wrap: wrap;
}

.auth-fields {
  display: flex;
  gap: 12px;
  align-items: flex-end;
  flex-wrap: wrap;
}

.auth-fields label {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--text-silver);
}

.action-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 24px;
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border-strong);
  font-size: 12px;
}

.action-banner.error {
  border-left: 4px solid var(--text-white);
  background: #1c1917;
}

.banner-close {
  background: none;
  border: none;
  color: var(--text-silver);
  font-size: 16px;
  cursor: pointer;
}

/* DEMO MODE PANEL */
.demo-guide-panel {
  margin: 16px 24px 0;
  padding: 18px 20px;
  background: var(--bg-charcoal);
  border: 1px solid var(--text-white);
}

.demo-step-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 12px;
}

.demo-title {
  font-size: 18px;
  font-weight: 700;
  margin-top: 2px;
}

.demo-subtitle {
  color: var(--text-silver);
  font-size: 12px;
}

.demo-nav-buttons {
  display: flex;
  gap: 8px;
}

.demo-step-pills {
  display: flex;
  gap: 6px;
  overflow-x: auto;
  padding-bottom: 10px;
  margin-bottom: 12px;
  border-bottom: 1px solid var(--border-subtle);
}

.demo-pill {
  background: var(--bg-black);
  color: var(--text-silver);
  border: 1px solid var(--border-subtle);
  padding: 5px 10px;
  font-family: var(--font-mono);
  font-size: 10px;
  white-space: nowrap;
  cursor: pointer;
}

.demo-pill.active {
  background: var(--text-white);
  color: var(--bg-black);
  border-color: var(--text-white);
  font-weight: 700;
}

.demo-narrative-grid {
  display: grid;
  grid-template-columns: 1.3fr 1fr;
  gap: 16px;
}

.demo-card {
  background: var(--bg-black);
  border: 1px solid var(--border-subtle);
  padding: 12px 14px;
}

.code-ref-badge {
  display: inline-block;
  padding: 3px 8px;
  background: var(--bg-elevated);
  border: 1px solid var(--border-strong);
  font-size: 11px;
  margin: 4px 0 8px;
}

.takeaway-text {
  color: var(--text-silver);
  margin-bottom: 10px;
}

/* MAIN WORKSPACE CONTAINER */
.workspace-container {
  padding: 20px 24px 40px;
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.workspace-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  gap: 16px;
  flex-wrap: wrap;
  border-bottom: 1px solid var(--border-subtle);
  padding-bottom: 12px;
}

.section-eyebrow {
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.12em;
  color: var(--text-muted);
  text-transform: uppercase;
}

.workspace-header h1 {
  font-size: 20px;
  font-weight: 700;
  margin-top: 2px;
}

.subview-switcher {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}

.sub-btn {
  background: var(--bg-charcoal);
  color: var(--text-silver);
  border: 1px solid var(--border-subtle);
  padding: 6px 12px;
  font-family: var(--font-mono);
  font-size: 11px;
  cursor: pointer;
}

.sub-btn.active {
  background: var(--text-white);
  color: var(--bg-black);
  border-color: var(--text-white);
  font-weight: 700;
}

/* ARCHITECTURE EXPLORER */
.arch-explorer-split {
  display: grid;
  grid-template-columns: 1.45fr 1fr;
  gap: 18px;
  align-items: start;
}

.arch-canvas-card {
  background: var(--bg-charcoal);
  border: 1px solid var(--border-subtle);
  padding: 14px;
}

.canvas-legend {
  display: flex;
  gap: 18px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-silver);
  margin-bottom: 10px;
  flex-wrap: wrap;
}

.legend-box {
  display: inline-block;
  width: 10px;
  height: 10px;
  margin-right: 6px;
  vertical-align: middle;
  border: 1px solid var(--text-white);
}

.arch-svg {
  width: 100%;
  height: auto;
  background: var(--bg-black);
  border: 1px solid var(--border-subtle);
}

.svg-node-group {
  cursor: pointer;
}

.arch-detail-panel {
  background: var(--bg-charcoal);
  border: 1px solid var(--border-strong);
  padding: 18px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.mono-badge {
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--text-silver);
}

.status-tag {
  display: inline-block;
  margin-top: 6px;
  padding: 3px 8px;
  background: var(--bg-elevated);
  border: 1px solid var(--border-strong);
  font-size: 11px;
}

.detail-section {
  border-top: 1px solid var(--border-subtle);
  padding-top: 10px;
}

.detail-grid-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.tag-list {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}

.code-chip,
.dep-chip {
  background: var(--bg-black);
  border: 1px solid var(--border-strong);
  color: var(--text-white);
  padding: 4px 8px;
  font-size: 11px;
}

.dep-chip {
  cursor: pointer;
}

.dep-chip:hover {
  background: var(--text-white);
  color: var(--bg-black);
}

.mono-list,
.compact-list {
  padding-left: 16px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.mono-list {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-silver);
}

.security-callout {
  background: var(--bg-black);
  border-left: 3px solid var(--text-white);
  padding: 8px 10px;
  color: var(--text-silver);
  font-size: 12px;
}

/* TABLES & MATRICES */
.table-card {
  background: var(--bg-charcoal);
  border: 1px solid var(--border-subtle);
  overflow-x: auto;
}

.card-Subheader {
  padding: 10px 14px;
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border-subtle);
  font-size: 11px;
  font-weight: 700;
}

.adaptos-table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
}

.adaptos-table th {
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--text-silver);
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-strong);
  background: var(--bg-black);
}

.adaptos-table td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-subtle);
  vertical-align: top;
}

.clickable-row {
  cursor: pointer;
}

.clickable-row:hover {
  background: var(--bg-elevated);
}

.status-pill-ok,
.status-pill-fail {
  display: inline-block;
  padding: 2px 7px;
  font-size: 10px;
  font-weight: 700;
  border: 1px solid var(--text-white);
}

.status-pill-ok {
  background: var(--text-white);
  color: var(--bg-black);
}

.status-pill-fail {
  background: transparent;
  color: var(--text-white);
  border-style: dashed;
}

.dataflow-grid,
.security-zones-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 14px;
}

.dataflow-card,
.sec-card {
  background: var(--bg-charcoal);
  border: 1px solid var(--border-subtle);
  padding: 14px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.df-header {
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  color: var(--text-silver);
  border-bottom: 1px solid var(--border-subtle);
  padding-bottom: 6px;
}

.df-contract {
  font-weight: 700;
  font-size: 13px;
}

/* WORKFLOW PIPELINE TRACK */
.workflow-pipeline-track {
  display: flex;
  align-items: stretch;
  gap: 6px;
  overflow-x: auto;
  padding: 12px;
  background: var(--bg-charcoal);
  border: 1px solid var(--border-subtle);
}

.wf-node-card {
  min-width: 175px;
  background: var(--bg-black);
  border: 1px solid var(--border-subtle);
  padding: 10px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  gap: 8px;
  cursor: pointer;
}

.wf-node-card.selected {
  border-color: var(--text-white);
  border-width: 2px;
}

.wf-node-card.status-completed {
  border-color: var(--border-strong);
}

.wf-node-card.status-active {
  background: var(--bg-elevated);
  border-color: var(--text-white);
}

.wf-node-top {
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  font-weight: 700;
}

.wf-badge {
  font-size: 9px;
  padding: 1px 5px;
  border: 1px solid var(--border-strong);
}

.wf-badge.completed,
.wf-badge.active {
  background: var(--text-white);
  color: var(--bg-black);
}

.wf-node-call {
  font-size: 10px;
  color: var(--text-silver);
  word-break: break-word;
}

.wf-loop-tag {
  font-size: 9px;
  color: var(--text-muted);
}

.btn-stage-run {
  background: var(--bg-charcoal);
  color: var(--text-white);
  border: 1px solid var(--border-strong);
  padding: 4px 8px;
  font-size: 10px;
  cursor: pointer;
}

.btn-stage-run:hover:not(:disabled) {
  background: var(--text-white);
  color: var(--bg-black);
}

.wf-connector {
  display: flex;
  align-items: center;
  color: var(--text-muted);
  font-size: 11px;
}

.workflow-bottom-grid {
  display: grid;
  grid-template-columns: 1fr 1.2fr;
  gap: 18px;
}

.wf-inspector-card,
.wf-logs-card {
  background: var(--bg-charcoal);
  border: 1px solid var(--border-subtle);
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.mono-box {
  background: var(--bg-black);
  border: 1px solid var(--border-subtle);
  padding: 8px 10px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-silver);
  word-break: break-all;
}

.event-log-stream {
  background: var(--bg-black);
  border: 1px solid var(--border-subtle);
  padding: 10px;
  max-height: 320px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 11px;
}

.event-line {
  display: flex;
  gap: 10px;
}

.event-idx {
  color: var(--text-muted);
}

/* VERIFICATION CENTER */
.verification-panel {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.trust-disclaimer-banner {
  background: var(--bg-elevated);
  border: 1px solid var(--text-white);
  padding: 10px 14px;
  font-size: 11px;
}

.metrics-row-4 {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
}

.metric-box {
  background: var(--bg-charcoal);
  border: 1px solid var(--border-subtle);
  padding: 12px 14px;
}

.metric-val {
  font-size: 15px;
  font-weight: 700;
  margin-top: 4px;
}

.api-gap-disclosure,
.empty-state {
  background: var(--bg-charcoal);
  border: 1px dashed var(--border-strong);
  padding: 16px;
  color: var(--text-silver);
}

.verdict-certificate-card,
.delivery-gate-card {
  background: var(--bg-charcoal);
  border: 1px solid var(--text-white);
  padding: 18px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.cert-header,
.delivery-gate-card {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  flex-wrap: wrap;
}

.verdict-giant-badge {
  font-size: 16px;
  font-weight: 800;
  padding: 8px 16px;
  border: 2px solid var(--text-white);
}

.verdict-giant-badge.verdict-ready {
  background: var(--text-white);
  color: var(--bg-black);
}

.cert-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 12px;
  background: var(--bg-black);
  border: 1px solid var(--border-subtle);
  padding: 14px;
  font-size: 11px;
}

.signature-box {
  background: var(--bg-black);
  border: 1px solid var(--border-strong);
  padding: 10px;
  font-size: 11px;
  word-break: break-all;
}

.download-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.manifest-meta-bar {
  display: flex;
  gap: 18px;
  padding: 8px 14px;
  background: var(--bg-black);
  border-bottom: 1px solid var(--border-subtle);
  font-size: 11px;
  color: var(--text-silver);
  flex-wrap: wrap;
}

.file-preview-block {
  padding: 12px 14px;
  border-bottom: 1px solid var(--border-subtle);
}

.code-pre {
  background: var(--bg-black);
  border: 1px solid var(--border-subtle);
  padding: 10px;
  font-size: 11px;
  overflow-x: auto;
  margin-top: 6px;
}

@media (max-width: 1024px) {
  .arch-explorer-split,
  .workflow-bottom-grid,
  .demo-narrative-grid {
    grid-template-columns: 1fr;
  }
}
`;

const styleEl = document.createElement("style");
styleEl.textContent = ADAPTOS_STYLES;
document.head.appendChild(styleEl);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);