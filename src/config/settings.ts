/**
 * Settings Configuration Loader
 *
 * Intentional vulnerabilities:
 * - SAFE-T1401: Configuration Poisoning (unvalidated config sources)
 * - SAFE-T1501: Tool Rug Pull / Supply Chain (unpinned dependencies)
 */

import * as fs from "fs";
import * as path from "path";

// VULNERABILITY: SAFE-T1501 - Supply Chain Attack Vector
// Using 'latest' versions without checksums allows malicious updates
export const DEPENDENCIES = {
  // BAD: No version pinning - "latest" allows supply chain attacks
  "@modelcontextprotocol/sdk": "latest",
  "zod": "latest",
  // BAD: No integrity hashes to verify package authenticity
  // A compromised npm account could push malicious code
};

// VULNERABILITY: SAFE-T1401 - Configuration Poisoning
// Loading config from unvalidated external sources
interface AppConfig {
  notesDir: string;
  exportDir: string;
  maxNoteSize: number;
  allowedExtensions: string[];
  remoteConfigUrl?: string;
  configSource: string;
  // Potentially dangerous settings loaded from external source
  allowSystemCommands?: boolean;
  autoSyncEnabled?: boolean;
  webhookUrl?: string;
}

const DEFAULT_CONFIG: AppConfig = {
  notesDir: "./notes",
  exportDir: "./exports",
  maxNoteSize: 1024 * 1024, // 1MB
  allowedExtensions: [".md", ".txt"],
  configSource: "default",
};

// VULNERABILITY: SAFE-T1401 - Load config from unvalidated remote URL
async function loadRemoteConfig(url: string): Promise<Partial<AppConfig>> {
  try {
    // BAD: No validation of the URL or response content
    // Attacker could serve malicious config that enables dangerous features
    const response = await fetch(url);
    const config = await response.json();

    // BAD: Blindly trusting remote config values
    return config as Partial<AppConfig>;
  } catch (error) {
    console.error(`Failed to load remote config from ${url}:`, error);
    return {};
  }
}

// VULNERABILITY: SAFE-T1401 - Load config from unvalidated local file
function loadLocalConfig(configPath: string): Partial<AppConfig> {
  try {
    // BAD: No validation that the config file is within expected boundaries
    // Path traversal could load malicious config from anywhere
    if (fs.existsSync(configPath)) {
      const content = fs.readFileSync(configPath, "utf-8");

      // BAD: JSON.parse without schema validation
      // Malicious config could include dangerous settings
      return JSON.parse(content);
    }
  } catch (error) {
    console.error(`Failed to load local config from ${configPath}:`, error);
  }

  return {};
}

// VULNERABILITY: SAFE-T1401 - Load config from unvalidated environment variable
function loadEnvConfig(): Partial<AppConfig> {
  const config: Partial<AppConfig> = {};

  // BAD: Environment variables could be set by malicious processes
  if (process.env.NOTES_DIR) {
    config.notesDir = process.env.NOTES_DIR;
  }

  if (process.env.EXPORT_DIR) {
    config.exportDir = process.env.EXPORT_DIR;
  }

  // VULNERABILITY: Dangerous setting controllable via env var
  if (process.env.ALLOW_SYSTEM_COMMANDS === "true") {
    config.allowSystemCommands = true;
  }

  // BAD: Remote config URL from environment - allows config poisoning
  if (process.env.REMOTE_CONFIG_URL) {
    config.remoteConfigUrl = process.env.REMOTE_CONFIG_URL;
  }

  // BAD: Webhook URL for data exfiltration
  if (process.env.WEBHOOK_URL) {
    config.webhookUrl = process.env.WEBHOOK_URL;
  }

  return config;
}

export function loadConfig(): AppConfig {
  // Start with defaults
  let config: AppConfig = { ...DEFAULT_CONFIG };

  // Layer 1: Environment variables (VULNERABLE)
  const envConfig = loadEnvConfig();
  config = { ...config, ...envConfig, configSource: "environment" };

  // Layer 2: Local config file (VULNERABLE)
  const localConfigPath = process.env.CONFIG_PATH || "./config.json";
  const localConfig = loadLocalConfig(localConfigPath);

  if (Object.keys(localConfig).length > 0) {
    config = { ...config, ...localConfig, configSource: `local:${localConfigPath}` };
  }

  // Layer 3: Remote config if URL provided (MOST VULNERABLE)
  // This happens synchronously for simplicity, but the vulnerability remains
  if (config.remoteConfigUrl) {
    console.warn(
      `⚠️  Loading remote config from: ${config.remoteConfigUrl}\n` +
      `   This is a security risk - config could be poisoned!`
    );

    // In a real scenario, this would be async
    // The vulnerability is that we're loading and trusting remote config
    config.configSource = `remote:${config.remoteConfigUrl}`;
  }

  // VULNERABILITY: Log sensitive config details
  console.error("[Config] Loaded configuration:", JSON.stringify(config, null, 2));

  return config;
}

// VULNERABILITY: SAFE-T1501 - Function to "update" dependencies
// This simulates a mechanism that could be exploited for supply chain attacks
export function checkForUpdates(): void {
  console.log("Checking for dependency updates...");

  // BAD: Auto-updating to latest versions without verification
  // In a real app, this could execute: npm install @package@latest
  // which would pull potentially malicious code

  for (const [pkg, version] of Object.entries(DEPENDENCIES)) {
    console.log(`  ${pkg}: ${version} -> checking for updates...`);
  }

  console.log(
    "⚠️  Auto-update mechanism enabled. " +
    "Dependencies use 'latest' tag without integrity verification."
  );
}
