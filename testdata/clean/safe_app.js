// Ordinary business logic. The identifiers contain "eval"/"exec" as a
// substring, but none is dangerous code execution — TRIAGE-001 must not flag
// them. No request access, crypto, or security TODOs here either.

function retrieval(records, key) {
  return records.filter((r) => r[key]);
}

function medievalTotal(items) {
  return items.reduce((sum, item) => sum + item.price, 0);
}

const planExecutor = {
  // A method whose name starts with "exec" is not a dynamic interpreter.
  execute(steps) {
    return steps.map((step) => step.run());
  },
};

function evaluateScore(values) {
  return values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0;
}

module.exports = { retrieval, medievalTotal, planExecutor, evaluateScore };
