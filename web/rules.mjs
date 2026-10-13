// Browser-only deterministic mirror of agents/workers.py.
// This is NOT SGX/SEV attestation, quote verification, or an HMAC audit service.
const CONFORMANCE_FLAGS = ["DISCORDANT", "ANOMALY", "MUTANT", "VIOLATION", "FAIL", "REJECT"];

export function evaluateTask(input) {
  const number = (value, label) => {
    if (value === null || value === undefined || String(value).trim() === "") {
      throw new Error(label + " is required.");
    }
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) throw new Error(label + " must be a finite number.");
    return parsed;
  };
  const identifier = (value, label) => {
    if (typeof value !== "string" || !value.trim() || value.trim().length > 128) {
      throw new Error(label + " must be 1–128 characters.");
    }
    return value.trim();
  };
  const task_id = identifier(input.task_id, "Task ID");
  const target_identifier = identifier(input.target_identifier, "Target");
  const status_descriptor = identifier(input.status_descriptor, "Status");
  const primary = number(input.primary_metric, "Primary metric");
  const secondary = number(input.secondary_metric, "Secondary metric");
  if (typeof input.is_critical_flag !== "boolean") throw new Error("Critical flag must be boolean.");
  const alerts = [];
  if (primary > 25) {
    alerts.push({
      origin_worker: "InvariantQCWorker", urgency: "ELEVATED_RISK",
      summary: "Primary Metric Threshold Exceeded",
      technical_details: "Primary value exceeds configured demonstration bound of 25.",
    });
  }
  if (input.is_critical_flag || secondary > 12) {
    alerts.push({
      origin_worker: "SafetyEscalationWorker",
      urgency: input.is_critical_flag ? "CRITICAL_STAT_PANIC" : "ELEVATED_RISK",
      summary: "Critical Safety Interlock Triggered",
      technical_details: "Critical flag or secondary demonstration bound (12) triggered.",
    });
  }
  if (CONFORMANCE_FLAGS.some(word => status_descriptor.toUpperCase().includes(word))) {
    alerts.push({
      origin_worker: "ProtocolConformanceWorker", urgency: "ELEVATED_RISK",
      summary: "Protocol Conformance Discordance Detected",
      technical_details: "The status descriptor contains a configured anomaly keyword.",
    });
  }
  const critical = alerts.filter(a => a.urgency === "CRITICAL_STAT_PANIC").length;
  const urgency = critical ? "CRITICAL_STAT_PANIC" : alerts.length ? "ELEVATED_RISK" : "ROUTINE";
  return {
    mode: "browser-only threshold simulation",
    hardware_attestation_verified: false,
    cryptographic_quote_verified: false,
    audit_hash: null,
    task_id, target_identifier, status_descriptor,
    primary_metric: primary, secondary_metric: secondary,
    is_critical_flag: input.is_critical_flag,
    overall_urgency: urgency,
    integrity_status: critical ? "RECALIBRATION_REQUIRED" : alerts.length ? "DISCORDANT_ANOMALY" : "VALIDATED_OPTIMAL",
    total_alerts: alerts.length,
    critical_alerts_count: critical,
    alerts,
  };
}
