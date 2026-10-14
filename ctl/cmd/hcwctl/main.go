// Command hcwctl is the command-line admin tool for the HiTechCloud WAF
// management API.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/ctl/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	app := &cli.App{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv}
	code := app.Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
