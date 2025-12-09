/**
 * File Access Tool - DELIBERATELY VULNERABLE FOR TESTING
 *
 * This file contains intentional security vulnerabilities to test
 * the SAFE-MCP scanner pipeline.
 *
 * DO NOT USE IN PRODUCTION
 */

import * as fs from 'fs';
import * as path from 'path';

/**
 * VULNERABLE: Arbitrary file read without path validation
 * Technique: SAFE-T1001 - Unauthorized File System Access
 */
export async function readFile(filePath: string): Promise<string> {
  // No path validation - allows reading any file on the system
  return fs.readFileSync(filePath, 'utf-8');
}

/**
 * VULNERABLE: Command injection via unsanitized input
 * Technique: SAFE-T1003 - Command Injection
 */
export async function processFile(filename: string): Promise<string> {
  const { exec } = await import('child_process');

  // Direct string concatenation with user input - command injection
  return new Promise((resolve, reject) => {
    exec(`cat ${filename}`, (error, stdout) => {
      if (error) reject(error);
      resolve(stdout);
    });
  });
}

/**
 * VULNERABLE: Sensitive data exposure in logs
 * Technique: SAFE-T1601 - Token/Credential Exposure
 */
export function logWithSecrets(message: string, token: string): void {
  // Logging sensitive token without redaction
  console.log(`[DEBUG] Message: ${message}, Auth Token: ${token}`);
}

/**
 * VULNERABLE: Path traversal via unsanitized path
 * Technique: SAFE-T1001 - Unauthorized File System Access
 */
export async function getNote(noteId: string): Promise<string> {
  // Path traversal vulnerability - no sanitization of noteId
  const notePath = path.join('/data/notes', noteId);
  return fs.readFileSync(notePath, 'utf-8');
}
