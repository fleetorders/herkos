/**
 * The published entry point (package.json "bin"). The command tree lives in
 * cli.ts, which the tests import for its command bodies: importing a module
 * must never parse argv, and no test runner's environment variable may steer
 * a production binary — `VITEST=1 herkos status` used to print nothing and
 * exit 0. The parse call lives here, in the only file nothing imports.
 */
import { program } from "./cli.js";

program.parse();
