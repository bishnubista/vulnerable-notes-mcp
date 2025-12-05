/**
 * Utility Helpers
 *
 * Intentional vulnerabilities:
 * - SAFE-T1101: Privilege Escalation (path traversal)
 * - SAFE-T1102: Cross-Agent Resource Access (shared state without auth)
 * - SAFE-T1802: System Detail Exfiltration (leaking system info)
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// VULNERABILITY: SAFE-T1802 - System Detail Exfiltration
// Returns detailed system information that could aid attackers
export function getSystemInfo(): Record<string, unknown> {
  return {
    // Operating system details
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    hostname: os.hostname(),

    // User information
    username: os.userInfo().username,
    homeDir: os.userInfo().homedir,
    shell: os.userInfo().shell,

    // System resources
    totalMemory: os.totalmem(),
    freeMemory: os.freemem(),
    cpus: os.cpus().length,
    uptime: os.uptime(),

    // Node.js details
    nodeVersion: process.version,
    nodePath: process.execPath,

    // Process details (sensitive!)
    pid: process.pid,
    ppid: process.ppid,
    cwd: process.cwd(),
    argv: process.argv,

    // Environment variables (VERY SENSITIVE!)
    // In a real attack, this would expose secrets
    envKeys: Object.keys(process.env),
    // Selectively expose some "safe" env vars that could still be useful to attackers
    nodeEnv: process.env.NODE_ENV,
    path: process.env.PATH,

    // Network interfaces (useful for lateral movement)
    networkInterfaces: Object.keys(os.networkInterfaces()),

    // Temporary directory (useful for staging attacks)
    tmpDir: os.tmpdir(),
  };
}

// VULNERABILITY: SAFE-T1101 - Privilege Escalation via Path Traversal
// No validation prevents access to files outside intended directory
export function readFile(baseDir: string, relativePath: string): string {
  // BAD: No validation of path traversal sequences
  // User can provide "../../etc/passwd" to read sensitive files
  const fullPath = path.join(baseDir, relativePath);

  // BAD: No check that resolved path is within baseDir
  // path.join doesn't prevent directory traversal
  return fs.readFileSync(fullPath, "utf-8");
}

// VULNERABILITY: SAFE-T1101 - More path traversal
export function writeFile(baseDir: string, relativePath: string, content: string): void {
  // BAD: Path traversal allows writing to arbitrary locations
  const fullPath = path.join(baseDir, relativePath);

  // Create directories if needed (could create directories outside baseDir!)
  const dir = path.dirname(fullPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(fullPath, content);
}

// VULNERABILITY: SAFE-T1101 - List files with path traversal
export function listFiles(baseDir: string, subPath: string = ""): string[] {
  // BAD: subPath could be "../../../" to list any directory
  const targetDir = path.join(baseDir, subPath);

  if (!fs.existsSync(targetDir)) {
    return [];
  }

  return fs.readdirSync(targetDir);
}

// VULNERABILITY: SAFE-T1102 - Cross-Agent Resource Access
// Shared state accessible without authentication
const SHARED_STATE_PATH = "/tmp/mcp-shared-state";

interface SharedState {
  [agentId: string]: {
    data: unknown;
    lastUpdated: string;
  };
}

// BAD: Any agent can read any other agent's state
export function getSharedState(agentId?: string): SharedState | unknown {
  try {
    if (!fs.existsSync(SHARED_STATE_PATH)) {
      return {};
    }

    const state: SharedState = JSON.parse(
      fs.readFileSync(SHARED_STATE_PATH, "utf-8")
    );

    // BAD: No authentication - any agent can read any state
    if (agentId) {
      return state[agentId]?.data;
    }

    // BAD: Returns ALL agents' state if no agentId specified
    return state;
  } catch (error) {
    return {};
  }
}

// BAD: Any agent can modify any other agent's state
export function setSharedState(agentId: string, data: unknown): void {
  let state: SharedState = {};

  if (fs.existsSync(SHARED_STATE_PATH)) {
    try {
      state = JSON.parse(fs.readFileSync(SHARED_STATE_PATH, "utf-8"));
    } catch {
      state = {};
    }
  }

  // BAD: No validation that caller has permission to modify this agentId's state
  // A malicious agent could overwrite another agent's data
  state[agentId] = {
    data,
    lastUpdated: new Date().toISOString(),
  };

  fs.writeFileSync(SHARED_STATE_PATH, JSON.stringify(state, null, 2));
}

// BAD: Any agent can delete any other agent's state
export function deleteSharedState(agentId: string): boolean {
  if (!fs.existsSync(SHARED_STATE_PATH)) {
    return false;
  }

  const state: SharedState = JSON.parse(
    fs.readFileSync(SHARED_STATE_PATH, "utf-8")
  );

  // BAD: No authentication check before deletion
  if (state[agentId]) {
    delete state[agentId];
    fs.writeFileSync(SHARED_STATE_PATH, JSON.stringify(state, null, 2));
    return true;
  }

  return false;
}

// VULNERABILITY: SAFE-T1802 - Leak environment details in formatted output
export function formatError(error: Error, context?: string): string {
  // BAD: Error formatting includes too much system detail
  return [
    `Error: ${error.message}`,
    `Context: ${context || "unknown"}`,
    `Stack: ${error.stack}`,
    `Working Directory: ${process.cwd()}`,
    `Node Version: ${process.version}`,
    `Platform: ${os.platform()} ${os.release()}`,
    `User: ${os.userInfo().username}`,
    `PID: ${process.pid}`,
    `Memory Usage: ${JSON.stringify(process.memoryUsage())}`,
  ].join("\n");
}

// VULNERABILITY: SAFE-T1102 - Expose inter-process communication
export function broadcastToAgents(message: string): void {
  // BAD: Writes message to shared location readable by all agents
  const broadcastPath = "/tmp/mcp-broadcast";

  const broadcasts = fs.existsSync(broadcastPath)
    ? JSON.parse(fs.readFileSync(broadcastPath, "utf-8"))
    : [];

  broadcasts.push({
    timestamp: new Date().toISOString(),
    message,
    // VULNERABILITY: Include sender system info
    sender: getSystemInfo(),
  });

  // Keep last 100 messages
  const trimmed = broadcasts.slice(-100);
  fs.writeFileSync(broadcastPath, JSON.stringify(trimmed, null, 2));
}
