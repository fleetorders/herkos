/**
 * Which tool arguments the hook reads.
 *
 * The hook used to be registered for two fixed tool names and read two fixed
 * argument names. Everything else — `Glob`, `NotebookEdit`, `PowerShell`, and
 * every tool-server (MCP) tool a user configures — reached the session without
 * passing the never-list at all, and a matcher list that must be edited each
 * time a harness grows a tool is a list that falls behind.
 *
 * So the hook matches EVERY tool and reads arguments by NAME, at any depth of
 * the argument object. Two vocabularies, because the two rule classes want
 * different subjects:
 *
 * - PATH_KEYS carry a filesystem path. Their values are matched against the
 *   path fragments of the never-list.
 * - COMMAND_KEYS carry something a shell or interpreter will execute. Their
 *   values are matched against BOTH the path fragments (a command that names a
 *   credential file) and the command patterns (fetched code piped to a shell).
 *
 * Deliberately NOT in either list, because the curation bar applies to the
 * matcher as much as to a rule:
 *
 * - `pattern` — a path glob in `Glob`, but a search expression in `Grep`, so
 *   searching a repository for the literal name of a token file would be
 *   refused. The directory-read half is covered natively by the harness's own
 *   deny rules, which understand the difference.
 * - `url` / `uri` — fetching is a different class from reading a local secret;
 *   a URL that merely contains a credential-shaped name is not a credential
 *   read.
 * - Free-text argument names (`content`, `new_string`, `prompt`, `query`,
 *   `description`) — documentation that names a credential file is not an
 *   attempt to read it, and blocking it would teach users to switch the guard
 *   off, which is worse than no guard.
 */

/** Argument names whose value is a filesystem path. */
export const PATH_KEYS: readonly string[] = [
  "file_path",
  "filePath",
  "file_paths",
  "filePaths",
  "path",
  "paths",
  "file",
  "files",
  "filename",
  "filenames",
  "notebook_path",
  "notebookPath",
  "dir",
  "directory",
  "folder",
  "absolute_path",
  "relative_path",
  "source",
  "destination",
  "source_path",
  "destination_path",
];

/** Argument names whose value is executed by a shell or an interpreter. */
export const COMMAND_KEYS: readonly string[] = [
  "command",
  "cmd",
  "commandLine",
  "command_line",
  "shell_command",
  "script",
  "code",
  "args",
  "argv",
];

/**
 * Tools whose every well-formed call carries an argument herkos expects to
 * read — a command (Bash, PowerShell) or a path (the file, notebook and
 * directory tools). Their arguments ARE the risk the never-list polices, so
 * they get no quiet treatment: a payload that parses cleanly but yields NO
 * readable value is schema drift (the harness renamed or restructured the very
 * keys the rules are checked against), and the call is announced UNCOVERED
 * exactly like an unknown tool — once per session and tool on the heard
 * channel, D-008 — instead of being muted into silent non-enforcement.
 *
 * Deliberately NOT here, though their names suggest it:
 * - `Glob` / `Grep` — their primary argument is `pattern`, which herkos
 *   deliberately does not read (a search naming a token file is not a read),
 *   so a call that yields nothing is their normal shape, not drift; announcing
 *   it would fire on every search and mute the guard.
 * - `WebFetch` / `WebSearch` — URLs and queries are never paths or commands
 *   in herkos's vocabularies; a zero-yield call is every call.
 */
export const PATH_BEARING_TOOLS: readonly string[] = [
  "Bash",
  "PowerShell",
  "Read",
  "Write",
  "Edit",
  "MultiEdit",
  "NotebookEdit",
  "NotebookRead",
  "LS",
];

/**
 * Tools whose argument shape herkos knows AND whose well-formed calls
 * legitimately carry nothing herkos reads — the quiet list. A call to a tool
 * OUTSIDE this list whose arguments carry none of the names above is reported
 * as uncovered — the honest answer, since herkos genuinely cannot see what it
 * would touch. Tools here stay quiet because an announcement on every call is
 * noise, and noise is how a guard gets muted; tools whose arguments are
 * themselves the risk sit in PATH_BEARING_TOOLS above instead, so schema drift
 * on them is announced rather than muted.
 */
export const KNOWN_TOOLS: readonly string[] = [
  "BashOutput",
  "KillBash",
  "KillShell",
  "Glob",
  "Grep",
  "WebFetch",
  "WebSearch",
  "Task",
  "Agent",
  "TodoWrite",
  "ExitPlanMode",
  "EnterPlanMode",
  "SlashCommand",
  "Skill",
  "AskUserQuestion",
  "ListMcpResources",
  "ReadMcpResource",
];
