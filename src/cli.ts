import path from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import {
  validateRepoPolicy,
  compileProjectPolicy,
  wireProject,
  verifyProject,
  unwireProject,
} from "./project.js";
import {
  loadEffectivePolicy,
  validatePolicy,
  compile,
  denyReadTargets,
  BASELINE,
  userPolicyPath,
} from "./policy.js";
import type { EffectivePolicy, ValidationResult } from "./policy.js";
import { ADAPTERS, detectInstalled } from "./adapters/index.js";
import type { WireResult } from "./adapters/types.js";
import { runSelfCheck, awkAvailable } from "./selfcheck.js";
import { readBlockLog, summariseBlocks } from "./blocklog.js";
import { runBypassCorpus } from "./corpus.js";
import type { CorpusResult, HarnessView } from "./corpus.js";
import { discoverCommand } from "./discover.js";
import { runLiveProbe, parsePositiveNumber } from "./probe.js";
import type { ProbeVerdict } from "./probe.js";

function printValidation(v: ValidationResult): void {
  for (const e of v.errors)
    process.stdout.write(`  ${pc.red("error:")} ${e}\n`);
  for (const w of v.warnings)
    process.stdout.write(`  ${pc.yellow("warning:")} ${w}\n`);
}

/**
 * Load the effective policy, or die trying with a one-line diagnosis: a
 * corrupt user policy file is a typo, and a typo is not a stack trace. Every
 * command that reads the policy goes through here, so `status`, `init`,
 * `check`, `rules`, `validate`, `discover` and `probe` all refuse cleanly.
 */
function loadPolicyOrExit(): EffectivePolicy {
  try {
    return loadEffectivePolicy();
  } catch (e) {
    process.stdout.write(pc.red(`herkos: ${(e as Error).message}\n`));
    process.exit(1);
  }
}

function initCmd(opts: { dryRun?: boolean }): void {
  const eff = loadPolicyOrExit();
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
  if (!awkAvailable()) {
    process.stdout.write(
      pc.yellow(
        "awk not found — the generated hook will announce enforcement OFF on every call until awk is available\n",
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
    let r: WireResult;
    try {
      r = a.wire(policy);
    } catch (e) {
      // A refusal from the adapter (e.g. harness settings of a shape herkos
      // cannot merge into) is a diagnosis, not a stack trace — and nothing
      // was written for that harness.
      process.stdout.write(
        pc.red(`herkos: could not wire ${a.name}: ${(e as Error).message}\n`),
      );
      process.exit(1);
    }
    process.stdout.write(`  ${pc.green("wired")} ${a.name}: ${r.detail}\n`);
  }
  if (!opts.dryRun)
    process.stdout.write(
      `\nRun ${pc.bold("herkos check")} to verify enforcement, ${pc.bold("herkos status")} to see wiring.\n`,
    );
}

function statusCmd(): void {
  const eff = loadPolicyOrExit();
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
    // Which layer holds each rule: a harness with several enforcement points of
    // different strength must say which one a rule actually rides.
    if (a.coverage) {
      const byLayer = new Map<string, string[]>();
      const bare: string[] = [];
      for (const c of a.coverage(compiled)) {
        if (c.layers.length === 0) bare.push(c.rule);
        for (const l of c.layers) {
          byLayer.set(l, [...(byLayer.get(l) ?? []), c.rule]);
        }
      }
      for (const [layer, rules] of byLayer) {
        process.stdout.write(
          `    ${pc.dim(`${layer}:`)} ${rules.join(", ")}\n`,
        );
      }
      if (bare.length > 0) {
        process.stdout.write(
          `    ${pc.red("NOT enforced here:")} ${bare.join(", ")}\n`,
        );
      }
    }
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

/**
 * The corpus report: the hook's verdict on each case is measured; the native
 * layers are credited only as each harness documents them and only where they
 * are wired here, and a case no wired layer holds is named, never hidden.
 */
function printCorpus(results: CorpusResult[]): void {
  const ran = results.filter((r) => !r.skipped).length;
  process.stdout.write(
    `\nbypass corpus — ${ran} case(s). The hook's verdict is measured here; other layers are credited as each harness documents them, and only where wired on this machine.\n`,
  );
  for (const r of results) {
    if (r.skipped) {
      process.stdout.write(`  ${pc.dim("skip")} ${r.case.id} — ${r.skipped}\n`);
      continue;
    }
    let hook: string;
    if (r.gotHook === "error") hook = "the hook errored";
    else if (r.case.benign && r.case.knownRefusal)
      hook =
        r.gotHook === "block"
          ? "refused — a documented known refusal"
          : "allowed — the documented refusal no longer happens; update this case and the docs";
    else if (r.case.benign)
      hook =
        r.gotHook === "pass"
          ? "allowed, as it must be"
          : "REFUSED a benign call";
    else if (r.gotHook === "block") hook = "hook blocks";
    else
      hook =
        r.case.hook === "pass"
          ? "hook passes (known gap)"
          : "hook passes — REGRESSION";
    const per = r.harnesses
      .filter((h) => h.verdict !== "n/a")
      .map((h) =>
        h.verdict === "held"
          ? `${h.name}: held by ${h.by.join(" + ")}`
          : `${h.name}: ${pc.yellow("UNGUARDED")}`,
      )
      .join(" · ");
    process.stdout.write(
      `  ${r.ok ? pc.green("ok  ") : pc.red("FAIL")} ${r.case.id} — ${hook}${per ? ` · ${per}` : ""}\n`,
    );
  }
  const names = [
    ...new Set(results.flatMap((r) => r.harnesses.map((h) => h.name))),
  ];
  for (const n of names) {
    const open = results
      .filter((r) =>
        r.harnesses.some((h) => h.name === n && h.verdict === "unguarded"),
      )
      .map((r) => r.case.id);
    if (open.length > 0) {
      process.stdout.write(
        `  ${pc.yellow(`${n}: ${open.length} case(s) no wired layer holds on this machine:`)} ${open.join(", ")}\n`,
      );
    }
  }
}

function checkCmd(): void {
  const effective = loadPolicyOrExit();
  const compiled = compile(effective);
  const v = validatePolicy(effective);
  printValidation(v);
  const s = runSelfCheck();
  // A policy that fails validation is not enforced as written: a rule grep
  // rejects is off at run time. That is a FAIL, not a warning.
  if (v.errors.length) s.ok = false;
  process.stdout.write(
    `herkos check — ${s.results.length} enforcement cases${s.awk ? "" : pc.yellow(" (warning: awk not found — the live hook degrades to allow)")}\n`,
  );
  process.stdout.write(
    `  ${v.errors.length ? pc.red("FAIL") : pc.green("ok  ")} policy validates${v.errors.length ? ` (${v.errors.length} error(s) — run 'herkos validate')` : ""}\n`,
  );
  for (const r of s.results) {
    process.stdout.write(
      `  ${r.ok ? pc.green("ok  ") : pc.red("FAIL")} ${r.name}${r.ok ? "" : ` (want exit ${r.wantExit}, got ${r.gotExit})`}\n`,
    );
  }
  const views: HarnessView[] = [];
  for (const a of ADAPTERS) {
    const d = a.detect();
    if (d.installed) {
      const v = a.verify();
      process.stdout.write(
        `  ${v.ok ? pc.green("ok  ") : pc.yellow("warn")} ${a.name} wiring: ${v.detail}\n`,
      );
      if (a.coverage) {
        views.push({
          name: a.name,
          hookScope: a.hookScope ?? "shell-commands",
          coverage: a.coverage(compiled),
        });
      }
    }
  }
  const corpus = runBypassCorpus(compiled, effective, views);
  printCorpus(corpus);
  if (corpus.some((r) => !r.ok)) s.ok = false;
  process.stdout.write(
    s.ok
      ? pc.green("\nPASS — the never-list is enforced\n")
      : pc.red("\nFAIL — enforcement did not behave as expected\n"),
  );
  process.exit(s.ok ? 0 : 1);
}

function rulesCmd(): void {
  const eff = loadPolicyOrExit();
  printValidation(validatePolicy(eff));
  for (const r of eff.rules) {
    const src = BASELINE.some((b) => b.id === r.id)
      ? pc.dim("[baseline]")
      : pc.cyan("[user]");
    const disp =
      r.disposition === "open"
        ? pc.yellow(" [open — notice, does not block]")
        : "";
    process.stdout.write(
      `  ${src} ${pc.bold(r.id)} (${r.class})${disp} — ${r.description}\n`,
    );
    if (r.message) {
      process.stdout.write(`      ${pc.dim(`message: ${r.message}`)}\n`);
    }
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
  const eff = loadPolicyOrExit();
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

function projectInitCmd(dir?: string): void {
  const repoRoot = path.resolve(dir ?? ".");
  const { effective, validation } = validateRepoPolicy(repoRoot);
  if (!effective.userPolicyLoaded) {
    process.stdout.write(
      `no herkos.json at ${repoRoot} — create one (a repo's own never-list) and re-run. See 'herkos project' help.\n`,
    );
    process.exit(1);
  }
  printValidation(validation);
  if (validation.errors.length) {
    process.stdout.write(
      pc.red(
        `herkos.json has ${validation.errors.length} error(s); nothing was written\n`,
      ),
    );
    process.exit(1);
  }
  if (effective.rules.length === 0) {
    process.stdout.write(
      `herkos.json declares no rules — nothing to compile.\n`,
    );
    process.exit(1);
  }
  const { compiled } = compileProjectPolicy(repoRoot);
  const r = wireProject(repoRoot, compiled);
  process.stdout.write(`${pc.green("wired project")}: ${r.detail}\n`);
  process.stdout.write(
    pc.dim(
      "Claude Code only — Codex config has no repo-local layer, so a repo's Codex sessions rest on the machine policy, not this list.\n",
    ),
  );
  process.stdout.write(
    `Commit ${pc.bold(".claude/")} and ${pc.bold("herkos.json")}, and add ${pc.bold("herkos project check")} to CI to catch drift.\n`,
  );
}

function projectCheckCmd(dir?: string): void {
  const repoRoot = path.resolve(dir ?? ".");
  const v = verifyProject(repoRoot);
  const mark = v.ok
    ? pc.green("ok  ")
    : v.state === "no-policy"
      ? pc.dim("n/a ")
      : pc.red("FAIL");
  process.stdout.write(`  ${mark} ${v.detail}\n`);
  // no-policy is not a failure (a repo may simply not use a project list); a
  // present-but-drifted or unwired policy is, so CI catches it.
  process.exit(v.ok || v.state === "no-policy" ? 0 : 1);
}

function projectUninstallCmd(dir?: string): void {
  const repoRoot = path.resolve(dir ?? ".");
  const r = unwireProject(repoRoot);
  process.stdout.write(`  ${r.detail}\n`);
}

function uninstallCmd(): void {
  for (const a of detectInstalled()) {
    const r = a.unwire();
    process.stdout.write(`  ${a.name}: ${r.detail}\n`);
  }
}

const DEFAULT_BUDGET_USD = 0.5;
const DEFAULT_TIMEOUT_S = 120;

/**
 * The live probe: opt-in, spends tokens, needs real auth. It never runs without
 * an explicit confirmation — a `--yes` flag, or a typed "yes" on a terminal.
 * Unattended without `--yes` it refuses and prints the exact command, so it can
 * never spend the user's tokens by accident.
 */
async function probeCmd(opts: {
  harness?: string;
  yes?: boolean;
  budgetUsd?: string;
  timeout?: string;
}): Promise<void> {
  loadPolicyOrExit(); // a corrupt policy is refused before anything runs
  // The ceilings are parsed and refused FIRST: a NaN budget or timeout must
  // exit before any harness is even detected, let alone run.
  let budgetUsd: number;
  let timeoutS: number;
  try {
    budgetUsd = parsePositiveNumber(
      opts.budgetUsd,
      "budget-usd",
      DEFAULT_BUDGET_USD,
    );
    timeoutS = parsePositiveNumber(opts.timeout, "timeout", DEFAULT_TIMEOUT_S);
  } catch (e) {
    process.stdout.write(pc.red(`herkos: ${(e as Error).message}\n`));
    process.exit(1);
  }
  const timeoutMs = Math.max(10, timeoutS) * 1000;
  const installed = detectInstalled().filter((a) => a.liveProbeCommand);
  const chosen = opts.harness
    ? installed.filter((a) => a.id === opts.harness)
    : installed;
  if (chosen.length === 0) {
    process.stdout.write(
      opts.harness
        ? `no installed harness with id '${opts.harness}' to probe\n`
        : "no installed harness supports a live probe\n",
    );
    process.exit(1);
  }
  const names = chosen.map((a) => a.name).join(", ");

  process.stdout.write(
    `herkos probe runs ONE real, headless agent session per harness (${names}) against your\n` +
      `installed wiring, to prove a block actually fires. It spends tokens and uses your real\n` +
      `auth. Ceiling per run: $${budgetUsd.toFixed(2)} where the harness supports a budget, and a\n` +
      `${timeoutMs / 1000}s timeout always. It reads only decoy files it plants, never a real secret.\n\n`,
  );

  if (!opts.yes) {
    if (!process.stdin.isTTY) {
      process.stdout.write(
        pc.yellow(
          "Refusing to spend tokens without confirmation. Re-run with --yes to proceed.\n",
        ),
      );
      process.exit(1);
    }
    const readline = await import("node:readline/promises");
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    const ans = (await rl.question('Type "yes" to run the live probe: '))
      .trim()
      .toLowerCase();
    rl.close();
    if (ans !== "yes") {
      process.stdout.write("Cancelled — nothing was run.\n");
      return;
    }
  }

  const reports = runLiveProbe(chosen, { budgetUsd, timeoutMs });
  const mark: Record<ProbeVerdict, string> = {
    blocked: pc.green("BLOCKED"),
    leaked: pc.red("LEAKED"),
    inconclusive: pc.yellow("inconclusive"),
    unavailable: pc.dim("unavailable"),
  };
  let leaked = false;
  for (const r of reports) {
    process.stdout.write(`\n${pc.bold(r.harness)} — ${r.note}\n`);
    if (!r.ran) continue;
    for (const o of r.outcomes) {
      if (o.verdict === "leaked") leaked = true;
      process.stdout.write(`  ${mark[o.verdict]} ${o.case} — ${o.detail}\n`);
    }
  }
  process.stdout.write(
    leaked
      ? pc.red(
          "\nA probe LEAKED — the installed wiring did not block a never-list action.\n",
        )
      : pc.green("\nNo leak: every probe was blocked or declined.\n"),
  );
  process.exit(leaked ? 1 : 0);
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
program
  .command("probe")
  .description(
    "opt-in: run a real headless session to prove a block fires (spends tokens)",
  )
  .option("--harness <id>", "probe only this harness (claude-code | codex)")
  .option(
    "--yes",
    "skip the confirmation prompt (required when not a terminal)",
  )
  .option(
    "--budget-usd <n>",
    `spend ceiling per run (default ${DEFAULT_BUDGET_USD})`,
  )
  .option(
    "--timeout <seconds>",
    `per-run timeout (default ${DEFAULT_TIMEOUT_S})`,
  )
  .action(probeCmd);
program
  .command("discover")
  .description(
    "find credential files on this machine that are not on the never-list (paths only)",
  )
  .option("--add <ids>", "add the named candidate rule ids without prompting")
  .option("--list", "only list; never prompt")
  .action(discoverCommand);

const project = program
  .command("project")
  .description(
    "per-repo policy: compile a repo's herkos.json into its Claude Code project layer",
  );
project
  .command("init [dir]")
  .description("compile <dir>/herkos.json into the repo's .claude project hook")
  .action(projectInitCmd);
project
  .command("check [dir]")
  .description(
    "verify the committed project hook matches herkos.json (for CI); exit 1 on drift",
  )
  .action(projectCheckCmd);
project
  .command("uninstall [dir]")
  .description("remove the herkos project wiring from the repo")
  .action(projectUninstallCmd);
// Under the test runner this module is imported, not executed as a program:
// vitest sets VITEST, and parsing the runner's own argv would exit the worker.
if (process.env.VITEST === undefined) program.parse();

/** The command bodies, for tests that exercise them without argv. */
export const __test = { initCmd, statusCmd, checkCmd, rulesCmd, validateCmd };
