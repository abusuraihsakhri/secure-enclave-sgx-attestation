import test from "node:test";
import assert from "node:assert/strict";
import { evaluateTask } from "../rules.mjs";

const example = {
  task_id: "T-01", target_identifier: "TARGET-01",
  primary_metric: 25, secondary_metric: 12,
  status_descriptor: "NOMINAL", is_critical_flag: false
};

test("boundary values are routine", () => {
  const r = evaluateTask(example);
  assert.equal(r.overall_urgency, "ROUTINE");
  assert.equal(r.total_alerts, 0);
  assert.equal(r.hardware_attestation_verified, false);
  assert.equal(r.audit_hash, null);
});
test("elevated metric generates an alert", () => {
  const r = evaluateTask({...example, primary_metric: 25.01});
  assert.equal(r.overall_urgency, "ELEVATED_RISK");
  assert.equal(r.total_alerts, 1);
});
test("critical flag escalates", () => {
  const r = evaluateTask({...example, is_critical_flag: true});
  assert.equal(r.overall_urgency, "CRITICAL_STAT_PANIC");
  assert.equal(r.critical_alerts_count, 1);
});
test("anomaly descriptor is evaluated", () => {
  assert.equal(evaluateTask({...example, status_descriptor: "anomaly"}).total_alerts, 1);
});
test("invalid and nonfinite metrics are rejected", () => {
  for (const value of ["", "NaN", Infinity, null]) {
    assert.throws(() => evaluateTask({...example, primary_metric: value}));
  }
});
test("text remains data, never rendered as HTML", () => {
  const value = "<img src=x onerror=alert(1)>";
  const result = evaluateTask({...example, task_id: value});
  assert.equal(result.task_id, value);
});
