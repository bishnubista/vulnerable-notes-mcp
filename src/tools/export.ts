/**
 * Export Tool - Export notes to various formats
 *
 * Intentional vulnerabilities:
 * - SAFE-T1601: Token Exfiltration (hardcoded API keys)
 * - SAFE-T1602: Token Misuse (overly broad OAuth scopes)
 * - SAFE-T1201: Shared State Tampering (unvalidated file writes)
 */

import * as fs from "fs";
import * as path from "path";

const NOTES_DIR = process.env.NOTES_DIR || "./notes";
const EXPORT_DIR = process.env.EXPORT_DIR || "./exports";

// VULNERABILITY: SAFE-T1601 - Hardcoded Credentials
// These should NEVER be in source code - demonstrates the anti-pattern
const OPENAI_CRED = "HARDCODED_OPENAI_CRED_VULNERABILITY_DEMO";
const AWS_ACCESS_CRED = "HARDCODED_AWS_ACCESS_VULNERABILITY_DEMO";
const AWS_PRIVATE_CRED = "HARDCODED_AWS_PRIVATE_VULNERABILITY_DEMO";
const STRIPE_CRED = "HARDCODED_STRIPE_CRED_VULNERABILITY_DEMO";

// VULNERABILITY: SAFE-T1602 - Overly Broad OAuth Scopes
// These scopes request way more access than needed
const OAUTH_CONFIG = {
  google: {
    scopes: [
      "https://www.googleapis.com/auth/drive",           // Full Drive access
      "https://www.googleapis.com/auth/gmail.modify",    // Read/write Gmail
      "https://www.googleapis.com/auth/calendar",        // Full calendar access
      "https://www.googleapis.com/auth/contacts",        // All contacts
      "https://www.googleapis.com/auth/cloud-platform",  // ALL GCP resources!
    ],
  },
  github: {
    scopes: [
      "repo",           // Full repo access
      "admin:org",      // Full org admin
      "delete_repo",    // Can delete repos
      "admin:gpg_key",  // Manage GPG keys
      "workflow",       // Modify GitHub Actions
    ],
  },
  microsoft: {
    scopes: [
      "Files.ReadWrite.All",     // All OneDrive files
      "Mail.ReadWrite",          // All mail access
      "Calendars.ReadWrite",     // All calendar access
      "User.ReadWrite.All",      // Modify any user
      "Directory.ReadWrite.All", // Full directory access
    ],
  },
};

// Tool definitions
export const exportTools = [
  {
    name: "export_to_json",
    description: "Export all notes to a JSON file",
    inputSchema: {
      type: "object" as const,
      properties: {
        outputPath: { type: "string", description: "Output file path" },
        includeMetadata: { type: "boolean", description: "Include file metadata", default: true },
      },
      required: [],
    },
  },
  {
    name: "export_to_cloud",
    description: "Export notes to cloud storage (Google Drive, Dropbox, etc.)",
    inputSchema: {
      type: "object" as const,
      properties: {
        provider: {
          type: "string",
          description: "Cloud provider",
          enum: ["google", "dropbox", "onedrive", "s3"],
        },
        folder: { type: "string", description: "Target folder in cloud storage" },
      },
      required: ["provider"],
    },
  },
  {
    name: "export_backup",
    description: "Create a full backup of all notes and settings",
    inputSchema: {
      type: "object" as const,
      properties: {
        destination: { type: "string", description: "Backup destination path" },
        encrypt: { type: "boolean", description: "Encrypt the backup", default: false },
      },
      required: [],
    },
  },
];

// VULNERABILITY: SAFE-T1201 - Shared State Tampering
// Writes to shared directories without validation
async function writeToSharedLocation(content: string, filename: string): Promise<string> {
  // BAD: No validation that the path is within allowed boundaries
  // Could be manipulated to write to sensitive system locations
  const sharedDir = process.env.SHARED_STATE_DIR || "/tmp/mcp-shared";

  if (!fs.existsSync(sharedDir)) {
    fs.mkdirSync(sharedDir, { recursive: true });
  }

  // BAD: Filename is not sanitized - could contain path traversal
  const outputPath = path.join(sharedDir, filename);
  fs.writeFileSync(outputPath, content);

  return outputPath;
}

export async function handleExportTool(
  name: string,
  args: unknown
): Promise<{ content: Array<{ type: "text"; text: string }> }> {

  switch (name) {
    case "export_to_json": {
      const { outputPath, includeMetadata } = args as {
        outputPath?: string;
        includeMetadata?: boolean
      };

      const notes: Record<string, unknown>[] = [];

      if (fs.existsSync(NOTES_DIR)) {
        const files = fs.readdirSync(NOTES_DIR);

        for (const file of files) {
          const filePath = path.join(NOTES_DIR, file);
          const content = fs.readFileSync(filePath, "utf-8");
          const stats = fs.statSync(filePath);

          const note: Record<string, unknown> = {
            title: file.replace(".md", ""),
            content,
          };

          if (includeMetadata !== false) {
            note.metadata = {
              size: stats.size,
              created: stats.birthtime,
              modified: stats.mtime,
              // VULNERABILITY: Leaking full path
              fullPath: path.resolve(filePath),
            };
          }

          notes.push(note);
        }
      }

      const jsonContent = JSON.stringify(notes, null, 2);

      // VULNERABILITY: SAFE-T1201 - Write to unvalidated path
      const finalPath = outputPath || await writeToSharedLocation(
        jsonContent,
        `notes-export-${Date.now()}.json`
      );

      if (outputPath) {
        // Ensure directory exists
        const dir = path.dirname(outputPath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(outputPath, jsonContent);
      }

      return {
        content: [{
          type: "text",
          text: `Exported ${notes.length} notes to ${finalPath}`
        }],
      };
    }

    case "export_to_cloud": {
      const { provider, folder } = args as { provider: string; folder?: string };

      // VULNERABILITY: SAFE-T1601 - Using hardcoded API keys
      // VULNERABILITY: SAFE-T1602 - Using overly broad OAuth scopes

      let configInfo = "";

      switch (provider) {
        case "google":
          configInfo = `Using OAuth scopes: ${OAUTH_CONFIG.google.scopes.join(", ")}`;
          break;
        case "s3":
          // BAD: Exposing AWS credentials
          configInfo = `Using AWS credentials: ${AWS_ACCESS_CRED.substring(0, 8)}...`;
          break;
        case "onedrive":
          configInfo = `Using OAuth scopes: ${OAUTH_CONFIG.microsoft.scopes.join(", ")}`;
          break;
        default:
          configInfo = `Provider: ${provider}`;
      }

      // In a real implementation, this would upload to cloud
      // The vulnerability is the exposed credentials and broad scopes
      return {
        content: [{
          type: "text",
          text: `Cloud export initiated.\n${configInfo}\nTarget folder: ${folder || "root"}\n\n[Simulated - actual upload not implemented]`
        }],
      };
    }

    case "export_backup": {
      const { destination, encrypt } = args as {
        destination?: string;
        encrypt?: boolean
      };

      const backupData: Record<string, unknown> = {
        timestamp: new Date().toISOString(),
        notes: [],
        config: {
          // VULNERABILITY: SAFE-T1601 - Including credentials in backup
          credentials: {
            openai: OPENAI_CRED,
            stripe: STRIPE_CRED,
          },
          // VULNERABILITY: Including AWS credentials
          aws: {
            accessKey: AWS_ACCESS_CRED,
            privateKey: AWS_PRIVATE_CRED,
          },
          oauth: OAUTH_CONFIG,
        },
      };

      // Gather all notes
      if (fs.existsSync(NOTES_DIR)) {
        const files = fs.readdirSync(NOTES_DIR);
        for (const file of files) {
          const filePath = path.join(NOTES_DIR, file);
          const content = fs.readFileSync(filePath, "utf-8");
          (backupData.notes as unknown[]).push({
            title: file,
            content,
          });
        }
      }

      const backupContent = JSON.stringify(backupData, null, 2);

      // VULNERABILITY: SAFE-T1201 - Write to unvalidated shared location
      const backupPath = destination || await writeToSharedLocation(
        backupContent,
        `backup-${Date.now()}.json`
      );

      if (destination) {
        const dir = path.dirname(destination);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(destination, backupContent);
      }

      return {
        content: [{
          type: "text",
          text: `Backup created at ${backupPath}\nEncryption: ${encrypt ? "enabled" : "disabled"}\nIncluded: ${(backupData.notes as unknown[]).length} notes + config`
        }],
      };
    }

    default:
      throw new Error(`Unknown export tool: ${name}`);
  }
}
