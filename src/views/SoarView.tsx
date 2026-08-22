import React, { useState } from "react";
import { useSoc } from "../context/SocContext";
import {
  Zap,
  Shield,
  Server,
  Key,
  Flame,
  CheckCircle2,
  XCircle,
  Clock,
  AlertCircle,
  Play,
  RotateCcw,
  ShieldCheck,
  History,
  FileCheck,
  Check,
  X,
  Ban
} from "lucide-react";
import type {
  SoarPlaybook,
  SoarPlaybookExecution,
  SoarConnectorInfo,
  SoarAuditLog
} from "../types/soc";

export const SoarView: React.FC = () => {
  const {
    soarPlaybooks,
    soarExecutions,
    soarConnectors,
    soarAuditLogs,
    soarLoading,
    executePlaybook,
    approveExecution,
    rejectExecution,
    cancelExecution,
    loadPlaybooks,
    loadPlaybookExecutions,
    loadSoarConnectors,
    loadSoarAuditLogs,
    incidents
  } = useSoc();

  const [activeTab, setActiveTab] = useState<"executions" | "playbooks" | "connectors" | "audit">("executions");
  const [selectedExecution, setSelectedExecution] = useState<SoarPlaybookExecution | null>(null);
  const [showRunModal, setShowRunModal] = useState<boolean>(false);
  const [selectedPlaybookToRun, setSelectedPlaybookToRun] = useState<SoarPlaybook | null>(null);
  const [runIncidentId, setRunIncidentId] = useState<string>("");
  const [isTriggering, setIsTriggering] = useState<boolean>(false);
  const [rejectionReason, setRejectionReason] = useState<string>("");
  const [showRejectModal, setShowRejectModal] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const handleApprove = async (executionId: string) => {
    try {
      await approveExecution(executionId, "Lead SOC Analyst");
      setActionMessage({ type: "success", text: `Execution ${executionId} approved and initiated.` });
      await loadPlaybookExecutions();
    } catch (err: any) {
      setActionMessage({ type: "error", text: `Approval failed: ${err.message || String(err)}` });
    }
  };

  const handleReject = async (executionId: string) => {
    if (!rejectionReason.trim()) return;
    try {
      await rejectExecution(executionId, "Lead SOC Analyst", rejectionReason);
      setShowRejectModal(null);
      setRejectionReason("");
      setActionMessage({ type: "success", text: `Execution ${executionId} rejected.` });
      await loadPlaybookExecutions();
    } catch (err: any) {
      setActionMessage({ type: "error", text: `Rejection failed: ${err.message || String(err)}` });
    }
  };

  const handleCancel = async (executionId: string) => {
    try {
      await cancelExecution(executionId, "Lead SOC Analyst", "Manual analyst cancellation");
      setActionMessage({ type: "success", text: `Execution ${executionId} cancelled.` });
      await loadPlaybookExecutions();
    } catch (err: any) {
      setActionMessage({ type: "error", text: `Cancellation failed: ${err.message || String(err)}` });
    }
  };

  const handleStartPlaybook = async () => {
    if (!selectedPlaybookToRun) return;
    setIsTriggering(true);
    try {
      const res = await executePlaybook(selectedPlaybookToRun.id, {
        initiatingUser: "Lead SOC Analyst",
        incidentId: runIncidentId || undefined
      });
      setShowRunModal(false);
      setSelectedExecution(res);
      setActionMessage({ type: "success", text: `Playbook '${selectedPlaybookToRun.name}' queued. Status: ${res.status}` });
    } catch (err: any) {
      setActionMessage({ type: "error", text: `Execution failed: ${err.message || String(err)}` });
    } finally {
      setIsTriggering(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "SUCCEEDED":
        return "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
      case "EXECUTING":
        return "bg-blue-500/20 text-blue-400 border border-blue-500/30 animate-pulse";
      case "APPROVAL_REQUIRED":
        return "bg-amber-500/20 text-amber-400 border border-amber-500/30";
      case "APPROVED":
        return "bg-indigo-500/20 text-indigo-400 border border-indigo-500/30";
      case "FAILED":
        return "bg-rose-500/20 text-rose-400 border border-rose-500/30";
      case "CANCELLED":
        return "bg-slate-700 text-slate-300 border border-slate-600";
      default:
        return "bg-slate-800 text-slate-400 border border-slate-700";
    }
  };

  const getConnectorIcon = (category: string) => {
    switch (category) {
      case "EDR":
        return <Shield className="w-5 h-5 text-indigo-400" />;
      case "FIREWALL":
        return <Flame className="w-5 h-5 text-orange-400" />;
      case "IDENTITY":
        return <Key className="w-5 h-5 text-amber-400" />;
      default:
        return <Server className="w-5 h-5 text-blue-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 backdrop-blur border border-slate-800 p-6 rounded-xl shadow-lg">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <Zap className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
                Production SOAR Orchestration & Connector Engine
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-medium">
                  Verified Engine
                </span>
              </h1>
              <p className="text-sm text-slate-400">
                Safe orchestration governance with authorization approval gates, idempotent bounded retries, and real vendor API connector isolation.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              if (soarPlaybooks.length > 0) {
                setSelectedPlaybookToRun(soarPlaybooks[0]);
                setShowRunModal(true);
              }
            }}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium transition shadow-md shadow-indigo-600/20"
          >
            <Play className="w-4 h-4" />
            Run SOAR Playbook
          </button>
        </div>
      </div>

      {actionMessage && (
        <div
          className={`p-4 rounded-lg text-sm flex items-center justify-between border ${
            actionMessage.type === "success"
              ? "bg-emerald-950/40 border-emerald-500/30 text-emerald-300"
              : "bg-rose-950/40 border-rose-500/30 text-rose-300"
          }`}
        >
          <span>{actionMessage.text}</span>
          <button onClick={() => setActionMessage(null)} className="text-xs font-bold opacity-80 hover:opacity-100">
            Dismiss
          </button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center gap-4 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab("executions")}
          className={`px-4 py-2 text-sm font-medium rounded-lg transition ${
            activeTab === "executions"
              ? "bg-slate-800 text-indigo-400 border border-slate-700"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          Active Executions ({soarExecutions.length})
        </button>
        <button
          onClick={() => setActiveTab("playbooks")}
          className={`px-4 py-2 text-sm font-medium rounded-lg transition ${
            activeTab === "playbooks"
              ? "bg-slate-800 text-indigo-400 border border-slate-700"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          Playbook Catalog ({soarPlaybooks.length})
        </button>
        <button
          onClick={() => setActiveTab("connectors")}
          className={`px-4 py-2 text-sm font-medium rounded-lg transition ${
            activeTab === "connectors"
              ? "bg-slate-800 text-indigo-400 border border-slate-700"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          Vendor Connectors ({soarConnectors.length})
        </button>
        <button
          onClick={() => setActiveTab("audit")}
          className={`px-4 py-2 text-sm font-medium rounded-lg transition ${
            activeTab === "audit"
              ? "bg-slate-800 text-indigo-400 border border-slate-700"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          SOAR Audit Logs ({soarAuditLogs.length})
        </button>
      </div>

      {/* Tab 1: Active Executions */}
      {activeTab === "executions" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-6 space-y-3">
            {soarExecutions.length === 0 ? (
              <div className="p-12 text-center bg-slate-900/40 border border-slate-800 rounded-xl">
                <Clock className="w-10 h-10 text-slate-600 mx-auto mb-3" />
                <h3 className="text-base font-medium text-slate-300">No SOAR Executions Recorded</h3>
                <p className="text-sm text-slate-500 mt-1">Run a playbook or trigger automatic response from an incident.</p>
              </div>
            ) : (
              soarExecutions.map((exec) => (
                <div
                  key={exec.id}
                  onClick={() => setSelectedExecution(exec)}
                  className={`p-4 rounded-xl border transition cursor-pointer ${
                    selectedExecution?.id === exec.id
                      ? "bg-slate-800/90 border-indigo-500/60 shadow-lg shadow-indigo-950/20"
                      : "bg-slate-900/60 border-slate-800/80 hover:bg-slate-800/50 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`px-2 py-0.5 text-xs font-semibold rounded ${getStatusBadge(exec.status)}`}>
                          {exec.status}
                        </span>
                        <span className="text-xs font-mono text-slate-500">{exec.id}</span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-200">{exec.playbookName}</h4>
                    </div>

                    {/* Quick Approval / Cancellation Buttons */}
                    {exec.status === "APPROVAL_REQUIRED" && (
                      <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => handleApprove(exec.id)}
                          className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium rounded flex items-center gap-1 shadow-sm transition"
                        >
                          <Check className="w-3.5 h-3.5" /> Approve
                        </button>
                        <button
                          onClick={() => setShowRejectModal(exec.id)}
                          className="px-2.5 py-1 bg-rose-600 hover:bg-rose-500 text-white text-xs font-medium rounded flex items-center gap-1 shadow-sm transition"
                        >
                          <X className="w-3.5 h-3.5" /> Reject
                        </button>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-slate-800/60">
                    <div>
                      Steps: <span className="text-slate-200 font-medium">{exec.currentStepIndex} / {exec.totalSteps}</span>
                    </div>
                    <div>
                      User: <span className="text-slate-300 font-mono">{exec.initiatingUser}</span>
                    </div>
                    <div>{new Date(exec.createdAt).toLocaleTimeString()}</div>
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Execution Details / Step Progress */}
          <div className="lg:col-span-6">
            {selectedExecution ? (
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-6 sticky top-6">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-2.5 py-1 text-xs font-semibold rounded ${getStatusBadge(selectedExecution.status)}`}>
                        {selectedExecution.status}
                      </span>
                      <span className="text-xs font-mono text-slate-500">{selectedExecution.id}</span>
                    </div>
                    <h3 className="text-lg font-bold text-slate-100">{selectedExecution.playbookName}</h3>
                  </div>

                  {selectedExecution.status === "APPROVAL_REQUIRED" && (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleApprove(selectedExecution.id)}
                        className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium rounded-lg flex items-center gap-1.5 transition"
                      >
                        <Check className="w-4 h-4" /> Approve Execution
                      </button>
                      <button
                        onClick={() => setShowRejectModal(selectedExecution.id)}
                        className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white text-xs font-medium rounded-lg flex items-center gap-1.5 transition"
                      >
                        <X className="w-4 h-4" /> Reject
                      </button>
                    </div>
                  )}

                  {["EXECUTING", "PENDING"].includes(selectedExecution.status) && (
                    <button
                      onClick={() => handleCancel(selectedExecution.id)}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg flex items-center gap-1.5 transition border border-slate-700"
                    >
                      <Ban className="w-4 h-4" /> Cancel Execution
                    </button>
                  )}
                </div>

                {/* Execution Metadata */}
                <div className="grid grid-cols-2 gap-3 p-3.5 bg-slate-950/60 rounded-lg border border-slate-800 text-xs">
                  <div>
                    <span className="text-slate-500">Initiating Actor:</span>
                    <p className="text-slate-200 font-mono">{selectedExecution.initiatingUser}</p>
                  </div>
                  <div>
                    <span className="text-slate-500">Linked Incident:</span>
                    <p className="text-indigo-400 font-mono">{selectedExecution.incidentId || "None"}</p>
                  </div>
                  <div>
                    <span className="text-slate-500">Approved By:</span>
                    <p className="text-slate-200 font-mono">{selectedExecution.approvedBy || "N/A"}</p>
                  </div>
                  <div>
                    <span className="text-slate-500">Idempotency Key:</span>
                    <p className="text-slate-400 font-mono truncate">{selectedExecution.idempotencyKey}</p>
                  </div>
                </div>

                {/* Steps Timeline */}
                <div>
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Playbook Action Steps</h4>
                  <div className="space-y-3">
                    {selectedExecution.stepsState.map((step, idx) => (
                      <div key={idx} className="p-3.5 bg-slate-950/50 rounded-lg border border-slate-800 space-y-2 text-xs">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="w-5 h-5 rounded-full bg-slate-800 text-slate-300 flex items-center justify-center font-bold text-[10px]">
                              {idx + 1}
                            </span>
                            <span className="font-semibold text-slate-200">{step.actionType}</span>
                          </div>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${getStatusBadge(step.status)}`}>
                            {step.status}
                          </span>
                        </div>

                        <div className="grid grid-cols-2 gap-2 text-slate-400 pt-1">
                          <div>
                            Target: <span className="text-slate-200 font-mono font-medium">{step.target}</span> ({step.targetType})
                          </div>
                          <div>
                            Connector: <span className="text-indigo-300 font-mono">{step.connectorId || "Pending"}</span>
                          </div>
                        </div>

                        {step.error && (
                          <div className="p-2 bg-rose-950/40 border border-rose-500/30 rounded text-rose-300 text-[11px] font-mono">
                            {step.error}
                          </div>
                        )}

                        {step.verificationResult && (
                          <div className="flex items-center gap-1.5 text-emerald-400 text-[11px] pt-1">
                            <ShieldCheck className="w-3.5 h-3.5 flex-shrink-0" />
                            <span>{step.verificationResult.message}</span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-12 text-center bg-slate-900/40 border border-slate-800 rounded-xl">
                <Clock className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                <p className="text-sm text-slate-400">Select an execution from the list to view its step-by-step containment progress.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Playbook Catalog */}
      {activeTab === "playbooks" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {soarPlaybooks.map((pb) => (
            <div key={pb.id} className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-mono text-indigo-400 bg-indigo-950/50 px-2 py-0.5 rounded border border-indigo-900/40">
                      v{pb.version}
                    </span>
                    <span className="text-xs text-slate-500 font-mono">{pb.id}</span>
                  </div>
                  <h4 className="text-base font-bold text-slate-200">{pb.name}</h4>
                </div>
                <button
                  onClick={() => {
                    setSelectedPlaybookToRun(pb);
                    setShowRunModal(true);
                  }}
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium rounded-lg flex items-center gap-1.5 transition"
                >
                  <Play className="w-3.5 h-3.5" /> Execute
                </button>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed">{pb.description}</p>

              <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 text-xs space-y-1">
                <div className="text-slate-500 font-semibold uppercase tracking-wider text-[10px]">Sequential Actions:</div>
                <div className="space-y-1 pt-1">
                  {pb.actions.map((act, i) => (
                    <div key={i} className="flex items-center gap-2 text-slate-300 font-mono text-[11px]">
                      <span className="text-indigo-400 font-bold">{i + 1}.</span>
                      <span className="font-semibold">{act.actionType}</span>
                      <span className="text-slate-500">→</span>
                      <span className="text-slate-400">{act.targetExpression}</span>
                      {act.requireVerification && (
                        <span className="text-[10px] text-emerald-400 bg-emerald-950/40 px-1 rounded border border-emerald-900/30">
                          Verify
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between text-xs text-slate-500 pt-2 border-t border-slate-800/60">
                <div>
                  Approval Required: <span className="font-bold text-slate-300">{pb.policy.requiresApproval ? "Yes" : "Auto"}</span>
                </div>
                <div>
                  Trigger: <span className="font-mono text-slate-400">{pb.triggerType}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 3: Connectors Fleet */}
      {activeTab === "connectors" && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {soarConnectors.map((conn) => (
            <div key={conn.id} className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-lg bg-slate-800 border border-slate-700">
                    {getConnectorIcon(conn.category)}
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-slate-200">{conn.name}</h4>
                    <p className="text-xs font-mono text-slate-500">{conn.id}</p>
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-slate-500">Status:</span>
                  <span
                    className={`px-2 py-0.5 text-xs font-bold rounded ${
                      conn.status === "HEALTHY"
                        ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                        : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                    }`}
                  >
                    {conn.status}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-normal">{conn.healthMessage}</p>
              </div>

              <div className="space-y-1 text-xs">
                <span className="text-slate-500 font-semibold uppercase text-[10px]">Capabilities:</span>
                <div className="flex flex-wrap gap-1 pt-1">
                  {conn.capabilities.map((cap, i) => (
                    <span key={i} className="px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-slate-300 font-mono text-[10px]">
                      {cap}
                    </span>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between text-xs text-slate-500 pt-2 border-t border-slate-800/60">
                <div>Rollback: {conn.supportsRollback ? "Supported" : "No"}</div>
                <div>Verification: {conn.supportsVerification ? "Supported" : "No"}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 4: Audit Logs */}
      {activeTab === "audit" && (
        <div className="space-y-3">
          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-2">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <History className="w-4 h-4 text-indigo-400" />
              Immutable SOAR Execution Audit Stream
            </h3>
            <p className="text-xs text-slate-400">
              Complete audit trail of all response actions, analyst authorizations, verification checks, and state transitions.
            </p>
          </div>

          <div className="divide-y divide-slate-800/80 bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
            {soarAuditLogs.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500">No audit logs recorded yet.</div>
            ) : (
              soarAuditLogs.map((log) => (
                <div key={log.id} className="p-3.5 hover:bg-slate-800/40 transition text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-indigo-300 font-mono">{log.eventType}</span>
                      <span className="text-slate-400">[{log.actionType}]</span>
                      <span className="text-slate-500 font-mono text-[11px]">{log.targetType}: {log.target}</span>
                    </div>
                    <span className="text-slate-500 font-mono text-[11px]">{new Date(log.timestamp).toLocaleString()}</span>
                  </div>
                  <div className="flex items-center gap-4 text-slate-400 text-[11px]">
                    <div>Actor: <span className="text-slate-300 font-medium">{log.actor}</span></div>
                    <div>Connector: <span className="font-mono text-slate-300">{log.connectorId}</span></div>
                    {log.incidentId && <div>Incident: <span className="font-mono text-indigo-400">{log.incidentId}</span></div>}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Manual Playbook Run Modal */}
      {showRunModal && selectedPlaybookToRun && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-5 shadow-2xl">
            <div>
              <h3 className="text-lg font-bold text-slate-100">Execute SOAR Playbook</h3>
              <p className="text-xs text-slate-400 mt-1">Playbook: {selectedPlaybookToRun.name}</p>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Target Incident ID (Optional)</label>
                <select
                  value={runIncidentId}
                  onChange={(e) => setRunIncidentId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 text-xs focus:outline-none focus:border-indigo-500"
                >
                  <option value="">-- No Linked Incident (Manual Standalone) --</option>
                  {incidents.map((inc) => (
                    <option key={inc.id} value={inc.id}>
                      {inc.id} - {inc.title} ({inc.severity})
                    </option>
                  ))}
                </select>
              </div>

              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
                <span className="text-slate-400 font-semibold">Planned Steps:</span>
                {selectedPlaybookToRun.actions.map((act, idx) => (
                  <div key={idx} className="font-mono text-slate-300 text-[11px]">
                    {idx + 1}. {act.actionType} ({act.targetExpression})
                  </div>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => setShowRunModal(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={handleStartPlaybook}
                disabled={isTriggering}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium rounded-lg transition flex items-center gap-2"
              >
                <Play className="w-3.5 h-3.5" />
                {isTriggering ? "Initiating..." : "Execute Playbook"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reject Modal */}
      {showRejectModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-slate-100">Reject Playbook Execution</h3>
            <p className="text-xs text-slate-400">Provide a mandatory reason for rejecting this automated response action.</p>

            <textarea
              rows={3}
              value={rejectionReason}
              onChange={(e) => setRejectionReason(e.target.value)}
              placeholder="e.g., Host is a primary mission-critical DC, alternative containment required..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-rose-500"
            />

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setShowRejectModal(null)}
                className="px-3 py-1.5 bg-slate-800 text-slate-300 text-xs font-medium rounded-lg"
              >
                Cancel
              </button>
              <button
                onClick={() => handleReject(showRejectModal)}
                disabled={!rejectionReason.trim()}
                className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-xs font-medium rounded-lg"
              >
                Confirm Rejection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
