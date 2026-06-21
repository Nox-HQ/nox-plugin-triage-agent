# Ordinary business logic. None of these are dangerous code execution — the
# identifiers merely contain "eval"/"exec" as a substring, and TRIAGE-001 must
# not flag them.


def retrieval(records, key):
    return [r for r in records if r.get(key)]


def medieval_total(items):
    return sum(item.price for item in items)


def execute_plan(steps):
    # A function whose name starts with "exec" is not the builtin interpreter.
    return [step.run() for step in steps]


def evaluate_score(values):
    return sum(values) / len(values) if values else 0
