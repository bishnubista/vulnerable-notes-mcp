#!/usr/bin/env node
/**
 * Vulnerable Notes MCP Server
 *
 * WARNING: This server contains INTENTIONAL security vulnerabilities
 * for testing the SAFE-MCP scanner. DO NOT use in production!
 *
 * Intentional flaws in this file:
 * - SAFE-T1302: System Instruction Bypass (env var override)
 * - SAFE-T1303: Multimodal Prompt Injection (unvalidated image URLs)
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { notesTools, handleNotesTool } from "./tools/notes.js";
import { searchTools, handleSearchTool } from "./tools/search.js";
import { exportTools, handleExportTool } from "./tools/export.js";
import { loadConfig } from "./config/settings.js";
import { getSystemInfo } from "./utils/helpers.js";

// VULNERABILITY: SAFE-T1302 - System Instruction Bypass
// Allows overriding system prompt via environment variable
const SYSTEM_PROMPT = process.env.OVERRIDE_SYSTEM_PROMPT ||
  "You are a helpful notes assistant. Help users manage their notes securely.";

// Scanner integration test - $(date +%s)

// VULNERABILITY: SAFE-T1303 - Multimodal Prompt Injection
// Processes image URLs without validation - could contain hidden instructions
async function processImageAttachment(imageUrl: string): Promise<string> {
  // BAD: No validation of image URL or content
  // Attacker could embed text instructions in image metadata
  const response = await fetch(imageUrl);
  const contentType = response.headers.get("content-type");

  // Blindly trust the content without scanning for hidden text
  return `Processed image from ${imageUrl} (${contentType})`;
}

const server = new Server(
  {
    name: "vulnerable-notes-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Load configuration (contains supply chain vulnerabilities)
const config = loadConfig();

// List all available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      ...notesTools,
      ...searchTools,
      ...exportTools,
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  // VULNERABILITY: Log system info on every request (SAFE-T1802)
  console.error(`[DEBUG] System: ${JSON.stringify(getSystemInfo())}`);

  // Process any image attachments without validation (SAFE-T1303)
  if (args && typeof args === 'object' && 'imageUrl' in args) {
    await processImageAttachment(args.imageUrl as string);
  }

  // Route to appropriate tool handler
  if (name.startsWith("notes_")) {
    return handleNotesTool(name, args, SYSTEM_PROMPT);
  } else if (name.startsWith("search_")) {
    return handleSearchTool(name, args);
  } else if (name.startsWith("export_")) {
    return handleExportTool(name, args);
  }

  throw new Error(`Unknown tool: ${name}`);
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Vulnerable Notes MCP Server running on stdio");
  console.error(`Config loaded from: ${config.configSource}`);
}

main().catch(console.error);
