import { Command } from "commander";
import pc from "picocolors";
import {
  loadEffectivePolicy,
  validatePolicy,
  compile,
  denyReadTargets,
  BASELINE,
  userPolicyPath,
} from "./policy.js";
import type { ValidationResult } from "./policy.js";
import { ADAPTERS, detectInstalled } from "./adapters/index.js";
import { runSelfCheck, jqAvailable } from "./selfcheck.js";
import { readBlockLog, summariseBlocks } from "./blocklog.js";

function printValidation(v: ValidationResult): void {
  for (const e of v.errors)
    process.stdout.write(`  ${pc.red("error:")} ${e}\n`);
  for (const w of v.warnings)
    process.stdout.write(`  ${pc.yellow("warning:")} ${w}\n`);
}

function initCmd(opts: { dryRun?: boolean }): void {
  const eff = loadEffectivePolicy();
  const v = validatePolicy(eff);
  if (v.errors.length) {
    printValidation(v);
    process.stdout.write(
      pc.red(`policy has ${v.errors.length} error(s); nothing was written\n`),
    );
    process.exit(1);
  }
  const policy = compile(eff);
  const installed = detectInstalled();
  process.stdout.write(
    `herkos — compiling ${policy.ruleCount} rules into installed harnesses\n`,
  );
  printValidation(v);
  if (!jqAvailable()) {
    process.stdout.write(
      pc.yellow(
        "jq not installed — the generated hook will announce enforcement OFF on every call until jq is installed\n",
      ),
    );
  }
  if (installed.length === 0) {
    process.stdout.write("  no supported harness detected on this machine\n");
    process.exit(1);
  }
  for (const a of installed) {
    const d = a.detect();
    if (opts.dryRun) {
      process.stdout.write(
        `  ${pc.dim("would wire")} ${a.name} (${d.version ?? "?"})\n`,
      );
      continue;
    }
    const r = a.wire(policy);
    process.stdout.write(`  ${pc.green("wired")} ${a.name}: ${r.detail}\n`);
  }
  if (!opts.dryRun)
    process.stdout.write(
      `\nRun ${pc.bold("herkos check")} to verify enforcement, ${pc.bold("herkos status")} to see wiring.\n`,
    );
}

function statusCmd(): void {
  const eff = loadEffectivePolicy();
  const compiled = compile(eff);
  process.stdout.write(
    `policy: ${eff.rules.length} rules (${eff.userPolicyLoaded ? "baseline + user" : "baseline only"}); user policy ${eff.userPolicyLoaded ? "at" : "would be at"} ${userPolicyPath()}\n`,
  );
  process.stdout.write(
    `  compiles to ${pc.bold(compiled.hash)} (herkos ${compiled.version}) — a wired hook reporting a different stamp is enforcing an older policy\n`,
  );
  printValidation(validatePolicy(eff));
  if (eff.disabled.length)
    process.stdout.write(
      `  disabled baseline rules: ${eff.disabled.join(", ")}\n`,
    );
  for (const a of ADAPTERS) {
    const d = a.detect();
    if (!d.installed) {
      process.stdout.write(`  ${pc.dim(a.name + ": not installed")}\n`);
      continue;
    }
    const v = a.verify();
    const label =
      v.state === "stale"
        ? pc.yellow(a.name + ": STALE")
        : v.ok
          ? pc.green(a.name + ": protected")
          : pc.yellow(a.name + ": NOT wired");
    process.stdout.write(`  ${label} — ${v.detail}\n`);
  }
  // What the guard has actually refused, per rule — the evidence for keeping,
  // narrowing or disabling a rule, and proof it ever fired at all.
  process.stdout.write(
    `blocked-call log: ${compiled.logFile ? `on, at ${compiled.logFile}` : `off ("log": false in the policy)`}\n`,
  );
  const blocks = summariseBlocks(readBlockLog());
  if (blocks.total === 0) {
    process.stdout.write(`  ${pc.dim("no blocks on record")}\n`);
  } else {
    const counts = Object.entries(blocks.perRule)
      .sort((a, b) => b[1] - a[1])
      .map(([rule, n]) => `${rule} ${n}`)
      .join(", ");
    process.stdout.write(`  ${blocks.total} block(s) on record — ${counts}\n`);
    for (const e of blocks.recent) {
      process.stdout.write(
        `  ${pc.dim(e.time)} ${e.harness} ${e.tool} ${pc.bold(e.rule)} in ${e.cwd}\n`,
      );
    }
  }
}

function checkCmd(): void {
  const v = validatePolicy(loadEffectivePolicy());
  printValidation(v);
  const s = runSelfCheck();
  // A policy that fails validation is not enforced as written: a rule grep
  // rejects is off at run time. That is a FAIL, not a warning.
  if (v.errors.length) s.ok = false;
  process.stdout.write(
    `herkos check — ${s.results.length} enforcement cases${s.jq ? "" : pc.yellow(" (warning: jq not installed — the live hook degrades to allow)")}\n`,
  );
  process.stdout.write(
    `  ${v.errors.length ? pc.red("FAIL") : pc.green("ok  ")} policy validates${v.errors.length ? ` (${v.errors.length} error(s) — run 'herkos validate')` : ""}\n`,
  );
  for (const r of s.results) {
    process.stdout.write(
      `  ${r.ok ? pc.green("ok  ") : pc.red("FAIL")} ${r.name}${r.ok ? "" : ` (want exit ${r.wantExit}, got ${r.gotExit})`}\n`,
    );
  }
  for (const a of ADAPTERS) {
    const d = a.detect();
    if (d.installed) {
      const v = a.verify();
      process.stdout.write(
        `  ${v.ok ? pc.green("ok  ") : pc.yellow("warn")} ${a.name} wiring: ${v.detail}\n`,
      );
    }
  }
  process.stdout.write(
    s.ok
      ? pc.green("\nPASS — the never-list is enforced\n")
      : pc.red("\nFAIL — enforcement did not behave as expected\n"),
  );
  process.exit(s.ok ? 0 : 1);
}

function rulesCmd(): void {
  const eff = loadEffectivePolicy();
  printValidation(validatePolicy(eff));
  for (const r of eff.rules) {
    const src = BASELINE.some((b) => b.id === r.id)
      ? pc.dim("[baseline]")
      : pc.cyan("[user]");
    process.stdout.write(
      `  ${src} ${pc.bold(r.id)} (${r.class}) — ${r.description}\n`,
    );
    const targets = denyReadTargets(r);
    if (targets.length > 0) {
      process.stdout.write(
        `      ${pc.dim(`native read deny: ${targets.join(", ")}`)}\n`,
      );
    }
  }
  if (eff.disabled.length)
    process.stdout.write(
      `  ${pc.yellow("disabled:")} ${eff.disabled.join(", ")}\n`,
    );
}

function validateCmd(): void {
  const eff = loadEffectivePolicy();
  const v = validatePolicy(eff);
  printValidation(v);
  if (v.errors.length) {
    process.stdout.write(pc.red(`\npolicy has ${v.errors.length} error(s)\n`));
    process.exit(1);
  }
  process.stdout.write(
    pc.green(`OK — policy valid (${eff.rules.length} rules)\n`),
  );
}

function uninstallCmd(): void {
  for (const a of detectInstalled()) {
    const r = a.unwire();
    process.stdout.write(`  ${a.name}: ${r.detail}\n`);
  }
}

const program = new Command();
program
  .name("herkos")
  .description(
    "Your never-list, enforced across every agent harness on this machine.",
  );
program
  .command("init")
  .description("compile the policy into every installed harness")
  .option("--dry-run", "show what would change")
  .action(initCmd);
program
  .command("status")
  .description("show policy + which harnesses are protected")
  .action(statusCmd);
program
  .command("check")
  .description(
    "prove the never-list is enforced (synthetic payloads) + verify wiring",
  )
  .action(checkCmd);
program
  .command("rules")
  .description("list the effective rules (baseline + user)")
  .action(rulesCmd);
program
  .command("validate")
  .description("check the policy file for errors before wiring")
  .action(validateCmd);
program
  .command("uninstall")
  .description("remove herkos wiring from installed harnesses")
  .action(uninstallCmd);
program.parse();
