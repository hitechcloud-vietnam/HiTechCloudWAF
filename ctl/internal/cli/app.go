// Package cli implements hcwctl, the command-line client of the
// HiTechCloud WAF management API.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Version is the hcwctl version, set at build time with
// -ldflags "-X github.com/hitechcloud-vietnam/HiTechCloudWAF/ctl/internal/cli.Version=v1.2.3".
var Version = "dev"

// App is one invocation of hcwctl. The zero value is not usable; set at
// least Stdin, Stdout, Stderr and Getenv.
type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	// ConfigPath overrides the profile file (default
	// $HCWCTL_CONFIG, else ~/.config/hcwctl/config.json).
	ConfigPath string
	// PollInterval is the events --follow interval (default 2s).
	PollInterval time.Duration

	in      *bufio.Reader
	profile string // --profile
	output  string // -o
}

// usageError is a wrong invocation; it exits with status 2.
type usageError struct {
	msg     string
	printed bool // the flag package already reported it
}

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// Run executes args (without the program name) and returns the exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	if a.Getenv == nil {
		a.Getenv = os.Getenv
	}
	if a.PollInterval <= 0 {
		a.PollInterval = 2 * time.Second
	}
	err := a.run(ctx, args)
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return exitOK
	}
	var ue *usageError
	if errors.As(err, &ue) {
		if !ue.printed {
			fmt.Fprintf(a.Stderr, "hcwctl: %s\n(run \"hcwctl help\" for usage)\n", ue.msg)
		}
		return exitUsage
	}
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(a.Stderr, "hcwctl: interrupted")
		return exitError
	}
	fmt.Fprintf(a.Stderr, "hcwctl: %v\n", err)
	return exitError
}

type command struct {
	name, args, help string
	run              func(*App, context.Context, []string) error
}

var commands []command

func init() {
	commands = []command{
		{"login", "--url URL [--user U | --token-file F] [--ca F | --insecure]", "save credentials in a profile", (*App).cmdLogin},
		{"logout", "", "forget the profile's credentials", (*App).cmdLogout},
		{"profiles", "[list | use NAME]", "list profiles or switch the current one", (*App).cmdProfiles},
		{"sites", "list | get ID | create -f FILE | update [ID] -f FILE | delete ID... |\n\t    set-mode ID block|monitor|off | deny-ip ID CIDR... |\n\t    allow-rule ID RULE... | disable-rule ID RULE...", "manage protected sites", (*App).cmdSites},
		{"certs", "list | add --crt F --key F [--domains a,b] | delete ID...", "manage TLS certificates", (*App).cmdCerts},
		{"events", "[--site N] [--limit N] [--follow]", "show security events", (*App).cmdEvents},
		{"stats", "", "per-site counters", (*App).cmdStats},
		{"upstreams", "", "upstream health", (*App).cmdUpstreams},
		{"audit", "[--limit N]", "administrative audit log", (*App).cmdAudit},
		{"users", "list | add NAME [--role admin|viewer] | delete NAME...", "manage console accounts", (*App).cmdUsers},
		{"backup", "[--file F]", "print the whole configuration as JSON (includes private keys)", (*App).cmdBackup},
		{"restore", "FILE [--yes]", "replace the whole configuration from a backup", (*App).cmdRestore},
		{"alerts", "test", "send a test notification", (*App).cmdAlerts},
		{"version", "[--client]", "show client and server versions", (*App).cmdVersion},
	}
}

func (a *App) usage(w io.Writer) {
	fmt.Fprintf(w, `hcwctl - command-line admin tool for HiTechCloud WAF

Usage: hcwctl [--profile NAME] [-o table|json] COMMAND [ARGS]

Commands:
`)
	for _, c := range commands {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.help)
		if c.args != "" {
			fmt.Fprintf(w, "  %-10s   hcwctl %s %s\n", "", c.name, c.args)
		}
	}
	fmt.Fprint(w, `
Global flags (accepted before or after the command):
  --profile NAME   profile from ~/.config/hcwctl/config.json (default: current)
  -o table|json    output format (default table)

Environment: HCWCTL_URL, HCWCTL_TOKEN, HCWCTL_CA (override the profile), HCWCTL_PROFILE,
HCWCTL_CONFIG, HCWCTL_PASSWORD, HCWCTL_OTP, HCWCTL_NEW_PASSWORD.
Exit status: 0 ok, 1 API or validation error, 2 usage error.
`)
}

func (a *App) run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("hcwctl", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	a.globalFlags(fs)
	fs.Usage = func() { a.usage(a.Stderr) }
	if err := fs.Parse(args); err != nil {
		return flagErr(err)
	}
	args = fs.Args()
	if len(args) == 0 {
		a.usage(a.Stderr)
		return &usageError{msg: "missing command", printed: true}
	}
	name, rest := args[0], args[1:]
	if name == "help" || name == "-h" {
		a.usage(a.Stdout)
		return nil
	}
	for _, c := range commands {
		if c.name == name {
			return c.run(a, ctx, rest)
		}
	}
	return usagef("unknown command %q", name)
}

func (a *App) globalFlags(fs *flag.FlagSet) {
	// Defaults are the current values so that flags given before the command
	// survive the subcommand's own flag set.
	fs.StringVar(&a.profile, "profile", a.profile, "profile name")
	if a.output == "" {
		a.output = "table"
	}
	fs.StringVar(&a.output, "o", a.output, "output format: table or json")
}

func flagErr(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return err
	}
	return &usageError{msg: err.Error(), printed: true}
}

// flags returns a flag set for "hcwctl <name>" with the global flags.
func (a *App) flags(name, args string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	a.globalFlags(fs)
	fs.Usage = func() {
		fmt.Fprintf(a.Stderr, "Usage: hcwctl %s %s\n\nFlags:\n", name, args)
		fs.PrintDefaults()
	}
	return fs
}

// parse parses flags interspersed with positional arguments and checks the
// number of positional arguments (max < 0: unlimited).
func (a *App) parse(fs *flag.FlagSet, args []string, min, max int) ([]string, error) {
	var pos, tail []string
	for i, s := range args {
		if s == "--" {
			args, tail = args[:i], args[i+1:]
			break
		}
	}
	for {
		if err := fs.Parse(args); err != nil {
			return nil, flagErr(err)
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	pos = append(pos, tail...)
	if a.output != "table" && a.output != "json" {
		return nil, usagef("-o must be table or json, not %q", a.output)
	}
	if len(pos) < min || (max >= 0 && len(pos) > max) {
		fs.Usage()
		switch {
		case len(pos) < min:
			return nil, &usageError{msg: "missing arguments", printed: true}
		default:
			return nil, &usageError{msg: "unexpected arguments: " + strings.Join(pos[max:], " "), printed: true}
		}
	}
	return pos, nil
}

func (a *App) json() bool { return a.output == "json" }

// sub dispatches "hcwctl <group> <sub> ...".
func (a *App) sub(ctx context.Context, group string, args []string, subs map[string]func(context.Context, []string) error, order string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintf(a.Stderr, "Usage: hcwctl %s %s\n", group, order)
		if len(args) == 0 {
			return &usageError{msg: "missing subcommand", printed: true}
		}
		return flag.ErrHelp
	}
	f, ok := subs[args[0]]
	if !ok {
		return usagef("unknown subcommand %q for %s (use %s)", args[0], group, order)
	}
	return f(ctx, args[1:])
}
