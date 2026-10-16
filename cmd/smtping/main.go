// Command smtping is the SMTPing CLI: verify email addresses and lists from a terminal,
// scripts, CI and AI agents. Same commands, output and exit codes as the npm CLI.
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	smtping "github.com/smtping/smtping-go"
)

var version = "dev" // set at build time by GoReleaser

const keysURL = "https://app.smtping.com"

const (
	exitOK        = 0
	exitError     = 1
	exitUsage     = 2
	exitAuth      = 3
	exitCredits   = 4
	exitRateLimit = 5
	exitAvoid     = 10
	exitJudgement = 11
)

var commands = []string{"auth", "login", "logout", "verify", "check", "bulk", "status", "results", "credits", "raw", "completion", "version", "help"}
var checkTypes = []string{"spamtrap", "disposable", "spambot", "complainer"}

const help = `SMTPing CLI %s

Usage
  smtping auth login [api-key]           Save your API key (asks for it if omitted)
  smtping auth status                    Show which key is used and the credits left
  smtping auth logout                    Remove the saved key
  smtping verify <email> [email...]      Verify one or more addresses
  smtping check <type> <email>           spamtrap | disposable | spambot | complainer
  smtping bulk <file> [--wait]           Submit a CSV or TXT file as one bulk job
  smtping status <job-id>                Progress of a bulk job
  smtping results <job-id>               Results of a finished job
  smtping credits                        Remaining credits
  smtping raw <METHOD> <path>            Call any API endpoint, e.g. raw GET /credits
  smtping completion <shell>             bash | zsh | fish | powershell

Options
  --key <key>          API key (else SMTPING_API_KEY, else the saved key)
  --json               JSON output (default when stdout is not a terminal)
  --table              Table output, even in a pipe
  --out <file>         Write results to a CSV file (bulk, results)
  --wait               Wait for the bulk job to finish (bulk)
  --fail-on <band>     Exit with a verdict code: avoid (10) or judgement (10 or 11)
  --data <json|@file>  Request body (raw)
  -y, --yes            Do not ask before spending credits on a bulk job
  -h, --help           Show help
  -v, --version        Show version

Exit codes
  0 ok, 1 error, 2 usage, 3 invalid key, 4 no credits, 5 rate limited,
  10 an address is avoid, 11 an address is judgement (with --fail-on)

Docs: https://smtping.com/cli
`

type args struct {
	pos     []string
	format  string
	wait    bool
	yes     bool
	key     string
	out     string
	failOn  string
	data    string
	help    bool
	version bool
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func parseArgs(argv []string) *args {
	a := &args{}
	next := func(i *int) string {
		if *i+1 < len(argv) {
			*i++
			return argv[*i]
		}
		return ""
	}
	for i := 0; i < len(argv); i++ {
		switch v := argv[i]; v {
		case "--json":
			a.format = "json"
		case "--table":
			a.format = "table"
		case "--wait":
			a.wait = true
		case "-y", "--yes":
			a.yes = true
		case "--key":
			a.key = next(&i)
		case "--out", "-o":
			a.out = next(&i)
		case "--fail-on":
			a.failOn = next(&i)
		case "--data", "-d":
			a.data = next(&i)
		case "-h", "--help":
			a.help = true
		case "-v", "--version":
			a.version = true
		default:
			a.pos = append(a.pos, v)
		}
	}
	if a.format == "" {
		if isTerminal(os.Stdout) {
			a.format = "table"
		} else {
			a.format = "json"
		}
	}
	return a
}

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "smtping", "config.json")
}

func savedKey() string {
	b, err := os.ReadFile(configPath())
	if err != nil {
		return ""
	}
	var c struct {
		APIKey string `json:"apiKey"`
	}
	_ = json.Unmarshal(b, &c)
	return c.APIKey
}

func keySource(a *args) (string, string) {
	if a.key != "" {
		return "--key", a.key
	}
	if k := os.Getenv("SMTPING_API_KEY"); k != "" {
		return "SMTPING_API_KEY", k
	}
	if k := savedKey(); k != "" {
		return configPath(), k
	}
	return "", ""
}

func fail(code int, format string, v ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", v...)
	os.Exit(code)
}

func newClient(key string) *smtping.Client {
	c, err := smtping.New(smtping.WithAPIKey(key), smtping.WithUserAgent("smtping-cli-go/"+version))
	if err != nil {
		fail(exitAuth, "%v", err)
	}
	return c
}

func client(a *args) *smtping.Client {
	_, key := keySource(a)
	if key == "" {
		fail(exitAuth, `No API key. Run "smtping auth login" or set SMTPING_API_KEY.`)
	}
	return newClient(key)
}

func mask(k string) string {
	if len(k) > 12 {
		return k[:8] + "..." + k[len(k)-4:]
	}
	return "****"
}

var useColor = isTerminal(os.Stdout) && os.Getenv("NO_COLOR") == ""

func paint(b smtping.Band, s string) string {
	if !useColor {
		return s
	}
	switch b {
	case smtping.BandSafe:
		return "\x1b[32m" + s + "\x1b[0m"
	case smtping.BandAvoid:
		return "\x1b[31m" + s + "\x1b[0m"
	}
	return "\x1b[33m" + s + "\x1b[0m"
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

type row struct {
	smtping.VerifyResult
	Band smtping.Band `json:"band"`
}

func withBands(rs []smtping.VerifyResult) []row {
	out := make([]row, len(rs))
	for i, r := range rs {
		out[i] = row{r, r.Band()}
	}
	return out
}

func printRows(rows []row) {
	w := 5
	for _, r := range rows {
		if len(r.Email) > w {
			w = len(r.Email)
		}
	}
	for _, r := range rows {
		fmt.Printf("%-*s  %s  %s  %s\n", w, r.Email, paint(r.Band, fmt.Sprintf("%-12s", r.Status)), paint(r.Band, fmt.Sprintf("%-9s", r.Band)), r.StatusDescription)
	}
}

func boolCell(b *bool) string {
	if b == nil {
		return ""
	}
	if *b {
		return "true"
	}
	return "false"
}

func writeCSV(file string, rows []row) {
	f, err := os.Create(file)
	if err != nil {
		fail(exitError, "%v", err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"email", "status", "band", "statusDescription", "isDisposable", "isFreeDomain", "isRoleBasedDomain", "isTypos"})
	for _, r := range rows {
		_ = w.Write([]string{r.Email, r.Status, string(r.Band), r.StatusDescription, boolCell(r.IsDisposable), boolCell(r.IsFreeDomain), boolCell(r.IsRoleBasedDomain), boolCell(r.IsTypos)})
	}
	w.Flush()
	fmt.Fprintf(os.Stderr, "Wrote %d rows to %s\n", len(rows), file)
}

var emailRe = regexp.MustCompile(`[^\s,;"'<>]+@[^\s,;"'<>]+\.[^\s,;"'<>]+`)

func emailsFromFile(file string) []string {
	b, err := os.ReadFile(file)
	if err != nil {
		fail(exitUsage, "File not found: %s", file)
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range emailRe.FindAllString(string(b), -1) {
		e = strings.ToLower(e)
		if smtping.IsEmail(e) && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}

func summary(rows []row) {
	c := map[smtping.Band]int{}
	for _, r := range rows {
		c[r.Band]++
	}
	fmt.Fprintf(os.Stderr, "\n%d verified: %d safe, %d avoid, %d judgement\n", len(rows), c[smtping.BandSafe], c[smtping.BandAvoid], c[smtping.BandJudgement])
}

func verdictExit(rows []row, a *args) int {
	code := exitOK
	for _, r := range rows {
		if r.Status == "error" {
			code = exitError
		}
	}
	if a.failOn == "" {
		return code
	}
	if a.failOn != "avoid" && a.failOn != "judgement" {
		fail(exitUsage, "--fail-on takes avoid or judgement.")
	}
	judgement := false
	for _, r := range rows {
		if r.Band == smtping.BandAvoid {
			return exitAvoid
		}
		if r.Band == smtping.BandJudgement {
			judgement = true
		}
	}
	if a.failOn == "judgement" && judgement {
		return exitJudgement
	}
	return code
}

func emit(rows []row, a *args) int {
	switch {
	case a.out != "":
		writeCSV(a.out, rows)
		summary(rows)
	case a.format == "json":
		printJSON(rows)
	default:
		printRows(rows)
		summary(rows)
	}
	return verdictExit(rows, a)
}

var stdin = bufio.NewReader(os.Stdin)

func ask(q string) string {
	fmt.Fprint(os.Stderr, q)
	line, _ := stdin.ReadString('\n')
	return strings.TrimSpace(line)
}

var ctrl = regexp.MustCompile(`\x1b\[[0-9;]*[~A-Za-z]|[^\x21-\x7e]`)

func login(ctx context.Context, key string) {
	if key == "" {
		if !isTerminal(os.Stdin) {
			fail(exitUsage, "Usage: smtping auth login <api-key>")
		}
		fmt.Fprintf(os.Stderr, "Create an API key in the SMTPing dashboard: %s (API keys).\n", keysURL)
		key = ask("Paste your API key: ")
	}
	key = ctrl.ReplaceAllString(key, "")
	if key == "" {
		fail(exitUsage, "No key entered.")
	}
	c, err := newClient(key).Credits(ctx)
	if err != nil {
		if errors.Is(err, smtping.ErrAuthentication) {
			fail(exitAuth, "Invalid API key (%d characters, starting with %s). Check it in %s, or pass it directly: smtping auth login <api-key>", len(key), key[:min(8, len(key))], keysURL)
		}
		fail(exitCodeFor(err), "%s", friendly(err))
	}
	p := configPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		fail(exitError, "%v", err)
	}
	b, _ := json.MarshalIndent(map[string]string{"apiKey": key}, "", "  ")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		fail(exitError, "%v", err)
	}
	fmt.Fprintf(os.Stderr, "Key %s saved to %s. Credits: %d%s\n", mask(key), p, c.Remaining, planSuffix(c.Plan))
}

func planSuffix(p string) string {
	if p == "" {
		return ""
	}
	return " (" + p + ")"
}

func confirmSpend(n int, a *args) {
	if a.yes {
		return
	}
	if !isTerminal(os.Stdin) {
		fail(exitUsage, "This job uses up to %d credits. Add --yes to run it without a terminal.", n)
	}
	ans := strings.ToLower(ask(fmt.Sprintf("Verify %d addresses, up to %d credits (unknown results are free). Continue? [y/N] ", n, n)))
	if ans != "y" && ans != "yes" {
		fail(exitUsage, "Cancelled.")
	}
}

func friendly(err error) string {
	switch {
	case errors.Is(err, smtping.ErrAuthentication):
		return `Invalid API key. Run "smtping auth login" or check SMTPING_API_KEY.`
	case errors.Is(err, smtping.ErrInsufficientCredits):
		return "Not enough credits. Top up at https://smtping.com/pricing"
	case errors.Is(err, smtping.ErrRateLimit):
		return "Rate limited. Wait a few seconds and try again."
	}
	return strings.TrimPrefix(err.Error(), "smtping: ")
}

func exitCodeFor(err error) int {
	switch {
	case errors.Is(err, smtping.ErrAuthentication):
		return exitAuth
	case errors.Is(err, smtping.ErrInsufficientCredits):
		return exitCredits
	case errors.Is(err, smtping.ErrRateLimit):
		return exitRateLimit
	}
	return exitError
}

func run(ctx context.Context, a *args) int {
	if a.version || (len(a.pos) > 0 && a.pos[0] == "version") {
		fmt.Println(version)
		return exitOK
	}
	if a.help || len(a.pos) == 0 || a.pos[0] == "help" {
		fmt.Printf(help, version)
		return exitOK
	}
	cmd, rest := a.pos[0], a.pos[1:]
	arg := func(i int) string {
		if i < len(rest) {
			return rest[i]
		}
		return ""
	}
	must := func(err error) {
		if err != nil {
			fail(exitCodeFor(err), "%s", friendly(err))
		}
	}

	switch cmd {
	case "auth":
		switch arg(0) {
		case "login":
			k := arg(1)
			if k == "" {
				k = a.key
			}
			login(ctx, k)
		case "logout":
			_ = os.Remove(configPath())
			fmt.Fprintln(os.Stderr, "Saved key removed.")
		case "status":
			src, key := keySource(a)
			if key == "" {
				fail(exitAuth, `Not logged in. Run "smtping auth login".`)
			}
			c, err := newClient(key).Credits(ctx)
			must(err)
			if a.format == "json" {
				printJSON(map[string]any{"key": mask(key), "source": src, "remaining": c.Remaining, "plan": c.Plan})
			} else {
				fmt.Printf("Key %s from %s\n%d credits%s\n", mask(key), src, c.Remaining, planSuffix(c.Plan))
			}
		default:
			fail(exitUsage, "Usage: smtping auth <login|status|logout>")
		}
	case "login":
		k := arg(0)
		if k == "" {
			k = a.key
		}
		login(ctx, k)
	case "logout":
		_ = os.Remove(configPath())
		fmt.Fprintln(os.Stderr, "Saved key removed.")
	case "verify":
		if len(rest) == 0 {
			fail(exitUsage, "Usage: smtping verify <email> [email...]")
		}
		rows := withBands(client(a).VerifyMany(ctx, rest, 5))
		if a.format == "json" {
			if len(rows) == 1 {
				printJSON(rows[0])
			} else {
				printJSON(rows)
			}
		} else {
			printRows(rows)
		}
		return verdictExit(rows, a)
	case "check":
		t, email := arg(0), arg(1)
		ok := false
		for _, c := range checkTypes {
			ok = ok || c == t
		}
		if !ok || email == "" {
			fail(exitUsage, "Usage: smtping check <spamtrap|disposable|spambot|complainer> <email>")
		}
		r, err := client(a).Check(ctx, smtping.Check(t), email)
		must(err)
		printJSON(r)
	case "credits":
		c, err := client(a).Credits(ctx)
		must(err)
		if a.format == "json" {
			printJSON(c)
		} else {
			fmt.Printf("%d credits%s\n", c.Remaining, planSuffix(c.Plan))
		}
	case "bulk":
		if arg(0) == "" {
			fail(exitUsage, "Usage: smtping bulk <file.csv|file.txt> [--wait] [--out results.csv] [--yes]")
		}
		emails := emailsFromFile(arg(0))
		if len(emails) == 0 {
			fail(exitUsage, "No email address found in the file.")
		}
		confirmSpend(len(emails), a)
		api := client(a)
		job, err := api.Bulk.Create(ctx, emails)
		must(err)
		fmt.Fprintf(os.Stderr, "Job %s created for %d unique addresses.\n", job.JobID, len(emails))
		if !a.wait {
			if a.format == "json" {
				printJSON(job)
			} else {
				fmt.Println(job.JobID)
				fmt.Fprintf(os.Stderr, "Check progress: smtping status %s\n", job.JobID)
			}
			return exitOK
		}
		tty := isTerminal(os.Stderr)
		res, err := api.Bulk.Wait(ctx, job.JobID, &smtping.WaitOptions{
			Timeout: 2 * time.Hour,
			OnProgress: func(j *smtping.BulkJob) {
				if tty {
					fmt.Fprintf(os.Stderr, "\r%d / %d verified", j.ProcessedEmails, len(emails))
				}
			},
		})
		if tty {
			fmt.Fprintln(os.Stderr)
		}
		must(err)
		return emit(withBands(res), a)
	case "status":
		if arg(0) == "" {
			fail(exitUsage, "Usage: smtping status <job-id>")
		}
		j, err := client(a).Bulk.Get(ctx, arg(0))
		must(err)
		if a.format == "json" {
			printJSON(j)
		} else {
			msg := ""
			if j.ErrorMessage != "" {
				msg = "  " + j.ErrorMessage
			}
			fmt.Printf("%s  %d / %d%s\n", j.Status, j.ProcessedEmails, j.TotalEmails, msg)
		}
	case "results":
		if arg(0) == "" {
			fail(exitUsage, "Usage: smtping results <job-id> [--out results.csv]")
		}
		res, err := client(a).Bulk.Results(ctx, arg(0))
		must(err)
		return emit(withBands(res), a)
	case "raw":
		method, p := strings.ToUpper(arg(0)), arg(1)
		if method == "" || p == "" {
			fail(exitUsage, "Usage: smtping raw <GET|POST|PUT|DELETE> <path> [--data <json|@file>]")
		}
		route := "/" + strings.TrimLeft(strings.TrimPrefix(strings.TrimLeft(p, "/"), "api/v1"), "/")
		var body any
		if a.data != "" {
			text := a.data
			if strings.HasPrefix(text, "@") {
				b, err := os.ReadFile(text[1:])
				if err != nil {
					fail(exitUsage, "%v", err)
				}
				text = string(b)
			}
			if err := json.Unmarshal([]byte(text), &body); err != nil {
				fail(exitUsage, "--data must be valid JSON.")
			}
		}
		var out any
		must(client(a).Request(ctx, method, route, body, &out))
		printJSON(out)
	case "completion":
		return completion(arg(0))
	default:
		fail(exitUsage, `Unknown command "%s". Run "smtping --help".`, cmd)
	}
	return exitOK
}

func completion(shell string) int {
	cmds := strings.Join(commands, " ")
	types := strings.Join(checkTypes, " ")
	opts := "--key --json --table --out --wait --fail-on --data --yes --help --version"
	quote := func(list []string) string {
		q := make([]string, len(list))
		for i, s := range list {
			q[i] = "'" + s + "'"
		}
		return strings.Join(q, ",")
	}
	scripts := map[string]string{
		"bash": `_smtping() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"; prev="${COMP_WORDS[COMP_CWORD-1]}"
  case "$prev" in
    smtping) COMPREPLY=($(compgen -W "` + cmds + `" -- "$cur")); return;;
    auth) COMPREPLY=($(compgen -W "login status logout" -- "$cur")); return;;
    check) COMPREPLY=($(compgen -W "` + types + `" -- "$cur")); return;;
    completion) COMPREPLY=($(compgen -W "bash zsh fish powershell" -- "$cur")); return;;
    raw) COMPREPLY=($(compgen -W "GET POST PUT DELETE" -- "$cur")); return;;
    --fail-on) COMPREPLY=($(compgen -W "avoid judgement" -- "$cur")); return;;
    bulk|--out) COMPREPLY=($(compgen -f -- "$cur")); return;;
  esac
  COMPREPLY=($(compgen -W "` + opts + `" -- "$cur"))
}
complete -F _smtping smtping
`,
		"zsh": `#compdef smtping
_smtping() {
  local -a cmds
  cmds=(` + cmds + `)
  case $words[2] in
    auth) _values 'auth' login status logout;;
    check) _values 'type' ` + types + `;;
    completion) _values 'shell' bash zsh fish powershell;;
    raw) _values 'method' GET POST PUT DELETE;;
    bulk) _files;;
    *) if (( CURRENT == 2 )); then _describe 'command' cmds; else _values 'option' ` + opts + `; fi;;
  esac
}
compdef _smtping smtping
`,
		"fish": `complete -c smtping -f
complete -c smtping -n "__fish_use_subcommand" -a "` + cmds + `"
complete -c smtping -n "__fish_seen_subcommand_from auth" -a "login status logout"
complete -c smtping -n "__fish_seen_subcommand_from check" -a "` + types + `"
complete -c smtping -n "__fish_seen_subcommand_from completion" -a "bash zsh fish powershell"
complete -c smtping -n "__fish_seen_subcommand_from raw" -a "GET POST PUT DELETE"
complete -c smtping -n "__fish_seen_subcommand_from bulk" -F
complete -c smtping -l key -r
complete -c smtping -l json
complete -c smtping -l table
complete -c smtping -l out -r -F
complete -c smtping -l wait
complete -c smtping -l fail-on -r -a "avoid judgement"
complete -c smtping -l data -r
complete -c smtping -s y -l yes
`,
		"powershell": `Register-ArgumentCompleter -Native -CommandName smtping -ScriptBlock {
  param($wordToComplete, $commandAst, $cursorPosition)
  $words = $commandAst.CommandElements | ForEach-Object { $_.ToString() }
  $list = switch ($words[1]) {
    'auth' { 'login','status','logout' }
    'check' { ` + quote(checkTypes) + ` }
    'completion' { 'bash','zsh','fish','powershell' }
    'raw' { 'GET','POST','PUT','DELETE' }
    default { if ($words.Count -le 2) { ` + quote(commands) + ` } else { ` + quote(strings.Fields(opts)) + ` } }
  }
  $list | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}
`,
	}
	s, ok := scripts[shell]
	if !ok {
		fmt.Fprint(os.Stderr, `Usage: smtping completion <bash|zsh|fish|powershell>

  bash        smtping completion bash > /etc/bash_completion.d/smtping
  zsh         smtping completion zsh > "${fpath[1]}/_smtping"
  fish        smtping completion fish > ~/.config/fish/completions/smtping.fish
  powershell  smtping completion powershell | Out-String | Invoke-Expression
`)
		return exitUsage
	}
	fmt.Print(s)
	return exitOK
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, parseArgs(os.Args[1:])))
}
