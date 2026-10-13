import { evaluateTask } from "./rules.mjs";

const form = document.getElementById("audit-form");
const output = document.getElementById("output");
const feedback = document.getElementById("status-message");
const download = document.getElementById("download");
let evaluations = 0;
let lastResult = null;

function setValue(id, value) { document.getElementById(id).value = value; }
const scenarios = {
  routine: [12, 4, "NOMINAL", false],
  elevated: [28, 13, "NOMINAL", false],
  critical: [29, 15, "DISCORDANT_ANOMALY", true],
};
for (const button of document.querySelectorAll("[data-scenario]")) {
  button.addEventListener("click", () => {
    const [primary, secondary, descriptor, critical] = scenarios[button.dataset.scenario];
    setValue("primary_metric", primary);
    setValue("secondary_metric", secondary);
    setValue("status_descriptor", descriptor);
    document.getElementById("is_critical_flag").checked = critical;
    feedback.textContent = "Example loaded. Select Evaluate locally.";
  });
}

form.addEventListener("submit", event => {
  event.preventDefault();
  try {
    lastResult = evaluateTask({
      task_id: document.getElementById("task_id").value,
      target_identifier: document.getElementById("target_identifier").value,
      primary_metric: document.getElementById("primary_metric").value,
      secondary_metric: document.getElementById("secondary_metric").value,
      status_descriptor: document.getElementById("status_descriptor").value,
      is_critical_flag: document.getElementById("is_critical_flag").checked,
    });
    evaluations += 1;
    output.textContent = JSON.stringify(lastResult, null, 2);
    document.getElementById("task-count").textContent = String(evaluations);
    document.getElementById("alert-count").textContent = String(lastResult.total_alerts);
    document.getElementById("outcome").textContent = lastResult.overall_urgency === "CRITICAL_STAT_PANIC"
      ? "Critical" : lastResult.overall_urgency === "ELEVATED_RISK" ? "Elevated" : "Routine";
    feedback.textContent = "Local rule evaluation complete. No cryptographic attestation performed.";
    download.disabled = false;
  } catch (error) {
    lastResult = null;
    download.disabled = true;
    output.textContent = "No valid result.";
    feedback.textContent = error.message;
  }
});

download.addEventListener("click", () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2) + "\n"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "threshold-evaluation.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
