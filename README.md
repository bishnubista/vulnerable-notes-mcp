# Vulnerable Notes MCP Server

> **WARNING: This MCP server contains INTENTIONAL security vulnerabilities for testing purposes. DO NOT use in production!**

A deliberately vulnerable MCP (Model Context Protocol) server designed for testing security scanning tools like [SAFE-MCP Scanner](https://github.com/SAFE-MCP/scanner).

## Purpose

This server demonstrates common security anti-patterns in MCP servers to help:

- Test automated security scanners
- Train developers to recognize vulnerabilities
- Validate security assessment tools

## Intentional Vulnerabilities

This server contains the following intentional security flaws:

| Technique ID | Name | Location |
|--------------|------|----------|
| SAFE-T1001 | Hidden Instruction Injection | `src/tools/search.ts` |
| SAFE-T1002 | Full-Schema Poisoning | `src/tools/search.ts` |
| SAFE-T1101 | Privilege Escalation | `src/utils/helpers.ts` |
| SAFE-T1102 | Cross-Agent Resource Access | `src/utils/helpers.ts` |
| SAFE-T1201 | Shared State Tampering | `src/tools/export.ts` |
| SAFE-T1301 | Direct Prompt Injection | `src/tools/notes.ts` |
| SAFE-T1302 | System Instruction Bypass | `src/index.ts` |
| SAFE-T1303 | Multimodal Prompt Injection | `src/index.ts` |
| SAFE-T1401 | Configuration Poisoning | `src/config/settings.ts` |
| SAFE-T1402 | Steganographic Instructions | `src/tools/search.ts` |
| SAFE-T1501 | Tool Rug Pull | `src/config/settings.ts` |
| SAFE-T1601 | Token Exfiltration | `src/tools/export.ts` |
| SAFE-T1602 | Token Misuse | `src/tools/export.ts` |
| SAFE-T1701 | Unauthorized Execution | `src/tools/notes.ts` |
| SAFE-T1801 | Sensitive Data Leakage | `src/tools/notes.ts` |
| SAFE-T1802 | System Detail Exfiltration | `src/utils/helpers.ts` |

## Installation

```bash
npm install
npm run build
```

## Usage

```bash
# Run the server
npm start

# Development mode (watch for changes)
npm run dev
```

## MCP Configuration

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "vulnerable-notes": {
      "command": "node",
      "args": ["dist/index.js"],
      "env": {
        "NOTES_DIR": "./notes"
      }
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `notes_create` | Create a new note |
| `notes_read` | Read a note by title |
| `notes_summarize` | Generate AI summary of a note |
| `notes_delete` | Delete a note |
| `notes_cleanup` | Auto-delete old notes |
| `search_notes` | Search through notes |
| `search_advanced` | Regex-based search |
| `search_by_date` | Search by date range |
| `export_to_json` | Export notes to JSON |
| `export_to_cloud` | Export to cloud storage |
| `export_backup` | Create full backup |

## Security Testing

To test with SAFE-MCP Scanner:

1. Install the SAFE-MCP GitHub App on this repository
2. Create a pull request with changes
3. The scanner will analyze the code and report findings
4. Review findings in the SAFE-MCP Platform

## License

MIT - For educational and testing purposes only.

## Disclaimer

This code is intentionally insecure. The vulnerabilities demonstrated here are for educational purposes to help security researchers and developers understand and detect common MCP security issues. Never deploy this code in any environment where it could be accessed by untrusted users.

<!-- Scanner test v3: Sat Dec 14 2025 -->
