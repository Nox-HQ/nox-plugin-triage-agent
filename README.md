# nox-plugin-triage-agent

**Automated security finding triage and prioritization for review workflows.**

## Overview

`nox-plugin-triage-agent` is a Nox security scanner plugin that prioritizes and classifies code patterns for security review. It categorizes findings into four priority tiers -- immediate, scheduled, backlog, and informational -- so security teams can focus their limited review bandwidth on the patterns that represent the greatest risk.

Security scanners produce findings. Triage determines which findings matter right now. A raw `eval()` call with user input demands immediate attention. Missing input validation is important but can be scheduled. A deprecated API is backlog work. A file that imports a crypto library is informational context. This plugin applies those priority judgments automatically, transforming an undifferentiated list of findings into a prioritized review queue.

The plugin scans Go, Python, JavaScript, and TypeScript source files. Each finding includes a `priority` metadata field (immediate, scheduled, backlog, informational) that enables downstream tooling to route findings to appropriate review workflows. All analysis is deterministic, offline, and read-only.

## Use Cases

### Security Team Review Queue Management

Your security team receives hundreds of scan findings per sprint and cannot review them all. The triage plugin classifies findings by priority so the team can focus on immediate items (dangerous code execution patterns) first, schedule reviews for medium-priority items (missing input validation), and track low-priority items (deprecated APIs) as backlog. This maximizes the security impact per hour of review time.

### Agent-Assisted Security Review

Your AI agents use Nox via MCP to perform initial security assessments. The triage plugin provides structured priority metadata that agents can use to generate executive summaries ("3 immediate findings require attention, 12 scheduled items for next sprint") and create prioritized work items in your issue tracker.

### Developer Self-Service Security Checks

Your developers run security scans locally before submitting pull requests. The triage plugin helps them understand which findings to fix before merging (immediate), which to create tickets for (scheduled), and which are informational context about security-relevant code areas. This reduces back-and-forth with the security team.

### Security Posture Trending

Your CISO tracks security posture over time. The triage plugin's consistent priority classification enables trending -- tracking whether the number of immediate-priority findings is decreasing sprint over sprint, whether backlog items are being addressed, and whether new code introduces more or fewer security-relevant patterns.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/Nox-HQ/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install Nox-HQ/nox-plugin-triage-agent
   ```

2. **Create test files with patterns across all priority levels**

   ```bash
   mkdir -p demo-triage && cd demo-triage

   cat > handler.py <<'EOF'
   import hashlib
   from flask import Flask, request
   import jwt
   import bcrypt

   app = Flask(__name__)

   @app.route("/execute")
   def run():
       code = request.args["code"]
       eval(code)

   @app.route("/api/user")
   def get_user():
       user_id = request.args["id"]
       user = db.get(user_id)
       return user.to_json()

   # TODO: add CSRF protection to payment endpoints - security issue
   @app.route("/pay")
   def process_payment():
       amount = request.json["amount"]
       return process(amount)

   def hash_password(password):
       return hashlib.md5(password.encode()).hexdigest()
   EOF

   cat > middleware.ts <<'EOF'
   import * as crypto from "crypto";
   import * as jwt from "jsonwebtoken";
   import helmet from "helmet";
   import cors from "cors";

   export function authenticate(req: Request): boolean {
       const token = req.headers["authorization"];
       return jwt.verify(token, process.env.SECRET);
   }
   EOF
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/triage-agent demo-triage/
   ```

4. **Review findings**

   ```
   nox/triage-agent scan completed: 5 findings

   TRIAGE-001 [HIGH] Critical security pattern requiring immediate review:
       eval(code)
     Location: demo-triage/handler.py:11
     Confidence: high
     Priority: immediate
     Language: python

   TRIAGE-002 [MEDIUM] High-priority pattern for scheduled review: missing input validation:
       user_id = request.args["id"]
     Location: demo-triage/handler.py:15
     Confidence: high
     Priority: scheduled
     Language: python

   TRIAGE-002 [MEDIUM] High-priority pattern for scheduled review: missing input validation:
       amount = request.json["amount"]
     Location: demo-triage/handler.py:22
     Confidence: high
     Priority: scheduled
     Language: python

   TRIAGE-003 [LOW] Low-priority hygiene pattern: deprecated API usage or security-related TODO:
       # TODO: add CSRF protection to payment endpoints - security issue
     Location: demo-triage/handler.py:19
     Confidence: medium
     Priority: backlog
     Language: python

   TRIAGE-004 [INFO] Informational pattern: security-relevant code area for review:
       import * as crypto from "crypto";
     Location: demo-triage/middleware.ts:1
     Confidence: high
     Priority: informational
     Language: typescript
   ```

## Rules

| Rule ID    | Description | Severity | Confidence | CWE | Priority |
|------------|-------------|----------|------------|-----|----------|
| TRIAGE-001 | Critical security pattern: dangerous code execution with user input -- `eval()`, `exec()`, `os.system()`, `subprocess.call(shell=True)`, `child_process.*`, `new Function()`, `vm.runInNewContext` | High | High | CWE-94 | immediate |
| TRIAGE-002 | Missing input validation: external data consumed without validation -- `request.args`, `request.form`, `request.json`, `req.body`, `req.query`, `req.params`, `r.URL.Query().Get()`, `r.FormValue()` | Medium | High | CWE-20 | scheduled |
| TRIAGE-003 | Hygiene pattern: security-related TODO/FIXME/HACK/XXX comments, deprecated APIs (`ioutil`, `md5`, `sha1`, `des`, `document.write`, `escape`, `unescape`) | Low | Medium | -- | backlog |
| TRIAGE-004 | Informational: security-relevant code areas -- crypto libraries, TLS/x509, JWT, bcrypt, OAuth, Passport, Helmet, CORS, CSRF middleware | Info | High | -- | informational |

## Supported Languages / File Types

| Language | Extensions |
|----------|-----------|
| Go | `.go` |
| Python | `.py` |
| JavaScript | `.js` |
| TypeScript | `.ts` |

## Configuration

The plugin operates with sensible defaults and requires no configuration. It scans the entire workspace recursively, skipping `.git`, `vendor`, `node_modules`, `__pycache__`, `.venv`, `dist`, and `build` directories.

Pass `workspace_root` as input to override the default scan directory:

```bash
nox scan --plugin nox/triage-agent --input workspace_root=/path/to/project
```

## Installation

### Via Nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-triage-agent
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-triage-agent.git
cd nox-plugin-triage-agent
make build
```

## Development

```bash
# Build the plugin binary
make build

# Run tests with race detection
make test

# Run linter
make lint

# Clean build artifacts
make clean

# Build Docker image
docker build -t nox-plugin-triage-agent .
```

## Architecture

The plugin follows the standard Nox plugin architecture, communicating via the Nox Plugin SDK over stdio.

1. **File Discovery**: Recursively walks the workspace, filtering for supported source file extensions (`.go`, `.py`, `.js`, `.ts`).

2. **Priority-Tiered Pattern Matching**: Each source file is scanned line by line against four tiers of compiled regex patterns:
   - **Tier 1 (immediate)**: Dangerous code execution patterns -- `eval()`, `exec()`, `os.system()`, `child_process`, `vm.runInNewContext` -- that represent direct code execution risk
   - **Tier 2 (scheduled)**: Input validation gaps -- request parameter access (`req.body`, `request.args`, `r.FormValue`) without surrounding validation logic
   - **Tier 3 (backlog)**: Code hygiene -- security-related TODO comments and deprecated API usage
   - **Tier 4 (informational)**: Context markers -- imports of security libraries (crypto, jwt, bcrypt, helmet, cors) that indicate security-relevant code areas

3. **Priority Metadata**: Each finding includes a `priority` metadata field set to `immediate`, `scheduled`, `backlog`, or `informational`. This enables downstream tooling (issue trackers, dashboards, agent workflows) to automatically route findings to appropriate queues.

4. **Deterministic Classification**: Priority assignment is based solely on which rule matched, not on heuristics or external data. The same code always receives the same priority classification.

## Contributing

Contributions are welcome. Please open an issue or submit a pull request on the [GitHub repository](https://github.com/Nox-HQ/nox-plugin-triage-agent).

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure `make test` and `make lint` pass
5. Submit a pull request

## License

Apache-2.0
