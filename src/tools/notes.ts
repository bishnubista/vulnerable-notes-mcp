/**
 * Notes Tool - CRUD operations for notes
 *
 * Intentional vulnerabilities:
 * - SAFE-T1301: Direct Prompt Injection (unsanitized user input in prompts)
 * - SAFE-T1701: Unauthorized Operation Execution (auto-delete without confirmation)
 * - SAFE-T1801: Sensitive Data Leakage (full paths in errors)
 * - SAFE-T1901: Server-Side Request Forgery (unvalidated URL fetching)
 */

import { z } from "zod";
import * as fs from "fs";
import * as path from "path";

const NOTES_DIR = process.env.NOTES_DIR || "./notes";

// Tool definitions
export const notesTools = [
  {
    name: "notes_create",
    description: "Create a new note with the given title and content",
    inputSchema: {
      type: "object" as const,
      properties: {
        title: { type: "string", description: "Title of the note" },
        content: { type: "string", description: "Content of the note" },
      },
      required: ["title", "content"],
    },
  },
  {
    name: "notes_read",
    description: "Read a note by its title",
    inputSchema: {
      type: "object" as const,
      properties: {
        title: { type: "string", description: "Title of the note to read" },
      },
      required: ["title"],
    },
  },
  {
    name: "notes_summarize",
    description: "Generate an AI summary of a note",
    inputSchema: {
      type: "object" as const,
      properties: {
        title: { type: "string", description: "Title of the note to summarize" },
        customPrompt: { type: "string", description: "Custom instructions for summarization" },
      },
      required: ["title"],
    },
  },
  {
    name: "notes_delete",
    description: "Delete a note by title. Executes immediately without confirmation.",
    inputSchema: {
      type: "object" as const,
      properties: {
        title: { type: "string", description: "Title of the note to delete" },
      },
      required: ["title"],
    },
  },
  {
    name: "notes_cleanup",
    description: "Automatically delete all notes older than specified days",
    inputSchema: {
      type: "object" as const,
      properties: {
        olderThanDays: { type: "number", description: "Delete notes older than this many days" },
      },
      required: ["olderThanDays"],
    },
  },
  {
    name: "notes_import_url",
    description: "Import a note from any URL. Fetches content and saves it as a new note.",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "URL to fetch content from. Supports any protocol the server can access.",
        },
        title: {
          type: "string",
          description: "Title for the imported note",
        },
        followRedirects: {
          type: "boolean",
          description: "Whether to follow HTTP redirects (default: true)",
        },
        timeout: {
          type: "number",
          description: "Request timeout in milliseconds (default: no timeout)",
        },
      },
      required: ["url", "title"],
    },
  },
];

// VULNERABILITY: SAFE-T1301 - Direct Prompt Injection
// User input is directly concatenated into prompt without sanitization
function buildSummaryPrompt(noteContent: string, customPrompt?: string): string {
  // BAD: Direct string concatenation allows prompt injection
  let prompt = `Please summarize the following note:\n\n${noteContent}`;

  if (customPrompt) {
    // BAD: Custom prompt from user is directly appended
    prompt += `\n\nAdditional instructions: ${customPrompt}`;
  }

  return prompt;
}

// VULNERABILITY: SAFE-T1801 - Sensitive Data Leakage
// Full file paths and system info leaked in error messages
function getNotePath(title: string): string {
  const sanitizedTitle = title.replace(/[^a-zA-Z0-9-_]/g, "_");
  return path.join(NOTES_DIR, `${sanitizedTitle}.md`);
}

export async function handleNotesTool(
  name: string,
  args: unknown,
  systemPrompt: string
): Promise<{ content: Array<{ type: "text"; text: string }> }> {

  try {
    switch (name) {
      case "notes_create": {
        const { title, content } = args as { title: string; content: string };
        const filePath = getNotePath(title);

        // Ensure directory exists
        if (!fs.existsSync(NOTES_DIR)) {
          fs.mkdirSync(NOTES_DIR, { recursive: true });
        }

        fs.writeFileSync(filePath, content);
        return {
          content: [{ type: "text", text: `Note "${title}" created successfully` }],
        };
      }

      case "notes_read": {
        const { title } = args as { title: string };
        const filePath = getNotePath(title);

        if (!fs.existsSync(filePath)) {
          // VULNERABILITY: SAFE-T1801 - Leaks full file path
          throw new Error(`Note not found at path: ${path.resolve(filePath)}`);
        }

        const content = fs.readFileSync(filePath, "utf-8");
        return {
          content: [{ type: "text", text: content }],
        };
      }

      case "notes_summarize": {
        const { title, customPrompt } = args as { title: string; customPrompt?: string };
        const filePath = getNotePath(title);

        if (!fs.existsSync(filePath)) {
          // VULNERABILITY: SAFE-T1801 - Leaks full path and working directory
          throw new Error(
            `Cannot summarize: Note not found.\n` +
            `Path: ${path.resolve(filePath)}\n` +
            `Working directory: ${process.cwd()}\n` +
            `Notes directory: ${path.resolve(NOTES_DIR)}`
          );
        }

        const content = fs.readFileSync(filePath, "utf-8");

        // VULNERABILITY: SAFE-T1301 - Prompt injection via customPrompt
        const prompt = buildSummaryPrompt(content, customPrompt);

        // In a real implementation, this would call an LLM
        // The vulnerability is the unsanitized prompt construction
        return {
          content: [{
            type: "text",
            text: `[Summary would be generated with prompt:]\n${prompt}`
          }],
        };
      }

      case "notes_delete": {
        const { title } = args as { title: string };
        const filePath = getNotePath(title);

        // VULNERABILITY: SAFE-T1701 - No confirmation required
        // Dangerous operation executes immediately
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
          return {
            content: [{ type: "text", text: `Note "${title}" deleted` }],
          };
        }

        return {
          content: [{ type: "text", text: `Note "${title}" not found` }],
        };
      }

      case "notes_cleanup": {
        const { olderThanDays } = args as { olderThanDays: number };
        const cutoffDate = Date.now() - (olderThanDays * 24 * 60 * 60 * 1000);
        let deletedCount = 0;

        // VULNERABILITY: SAFE-T1701 - Bulk delete without confirmation
        // Could delete many files without user approval
        if (fs.existsSync(NOTES_DIR)) {
          const files = fs.readdirSync(NOTES_DIR);
          for (const file of files) {
            const filePath = path.join(NOTES_DIR, file);
            const stats = fs.statSync(filePath);

            if (stats.mtimeMs < cutoffDate) {
              fs.unlinkSync(filePath);
              deletedCount++;
            }
          }
        }

        return {
          content: [{
            type: "text",
            text: `Cleanup complete: ${deletedCount} notes deleted automatically`
          }],
        };
      }

      case "notes_import_url": {
        // VULNERABILITY: SAFE-T1901 - Server-Side Request Forgery (SSRF)
        // No validation of URL scheme, host, or port
        // Allows access to internal network resources, cloud metadata, local files
        const { url, title, followRedirects = true, timeout } = args as {
          url: string;
          title: string;
          followRedirects?: boolean;
          timeout?: number;
        };

        const filePath = getNotePath(title);

        // BAD: No URL validation at all
        // - Allows file:// protocol to read local files
        // - Allows access to internal IPs (127.0.0.1, 10.x.x.x, 192.168.x.x)
        // - Allows access to cloud metadata (169.254.169.254)
        // - Allows access to internal services on any port
        // - No blocklist for sensitive endpoints

        const fetchOptions: RequestInit = {
          redirect: followRedirects ? "follow" : "manual",
          // BAD: No timeout by default allows slow-loris attacks
          signal: timeout ? AbortSignal.timeout(timeout) : undefined,
        };

        // BAD: Blindly fetch any URL provided by user
        const response = await fetch(url, fetchOptions);

        // BAD: Expose internal response details
        const responseInfo = {
          status: response.status,
          statusText: response.statusText,
          headers: Object.fromEntries(response.headers.entries()),
          url: response.url, // Exposes final URL after redirects
          redirected: response.redirected,
        };

        const content = await response.text();

        // Ensure directory exists
        if (!fs.existsSync(NOTES_DIR)) {
          fs.mkdirSync(NOTES_DIR, { recursive: true });
        }

        // BAD: Save content without any sanitization
        // Could contain malicious payloads, scripts, etc.
        const noteContent = `# Imported from: ${url}\n\n` +
          `## Response Info\n` +
          `- Status: ${responseInfo.status} ${responseInfo.statusText}\n` +
          `- Final URL: ${responseInfo.url}\n` +
          `- Redirected: ${responseInfo.redirected}\n` +
          `- Headers: ${JSON.stringify(responseInfo.headers, null, 2)}\n\n` +
          `## Content\n\n${content}`;

        fs.writeFileSync(filePath, noteContent);

        // BAD: Return internal response details to attacker
        return {
          content: [{
            type: "text",
            text: `Note "${title}" imported from ${url}\n\n` +
              `Response Details:\n${JSON.stringify(responseInfo, null, 2)}\n\n` +
              `Content length: ${content.length} bytes\n` +
              `Saved to: ${path.resolve(filePath)}`
          }],
        };
      }

      default:
        throw new Error(`Unknown notes tool: ${name}`);
    }
  } catch (error) {
    // VULNERABILITY: SAFE-T1801 - Full error details exposed
    const errorMessage = error instanceof Error ? error.message : String(error);
    const stack = error instanceof Error ? error.stack : "";

    return {
      content: [{
        type: "text",
        text: `Error: ${errorMessage}\n\nStack trace:\n${stack}`
      }],
    };
  }
}
