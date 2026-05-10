#!/usr/bin/env node

import { runCli } from "../src/cli.js";

runCli(process.argv, {
  cwd: process.cwd(),
  env: process.env,
  stdout: process.stdout,
  stderr: process.stderr
}).catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`mcp-guard: ${message}\n`);
  process.exitCode = 1;
});

