package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

func (a *App) reader() *bufio.Reader {
	if a.in == nil {
		a.in = bufio.NewReader(a.Stdin)
	}
	return a.in
}

// stdinTerminal returns stdin when it is an interactive terminal.
func (a *App) stdinTerminal() *os.File {
	f, ok := a.Stdin.(*os.File)
	if !ok {
		return nil
	}
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return nil
	}
	return f
}

// readLine prompts on stderr and reads one line from stdin.
func (a *App) readLine(ctx context.Context, prompt string) (string, error) {
	fmt.Fprint(a.Stderr, prompt)
	type res struct {
		s   string
		err error
	}
	ch := make(chan res, 1)
	r := a.reader()
	go func() {
		s, err := r.ReadString('\n')
		if errors.Is(err, io.EOF) && s != "" {
			err = nil
		}
		ch <- res{strings.TrimRight(s, "\r\n"), err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case v := <-ch:
		if errors.Is(v.err, io.EOF) {
			return "", errors.New("no input on stdin")
		}
		return v.s, v.err
	}
}

// readSecret reads a line without echo when stdin is a terminal. It uses
// stty so that only the standard library is needed; where stty is missing
// the input is echoed.
func (a *App) readSecret(ctx context.Context, prompt string) (string, error) {
	f := a.stdinTerminal()
	if f == nil {
		return a.readLine(ctx, prompt)
	}
	stty := func(arg string) error {
		cmd := exec.Command("stty", arg)
		cmd.Stdin = f
		return cmd.Run()
	}
	if err := stty("-echo"); err == nil {
		defer func() {
			_ = stty("echo")
			fmt.Fprintln(a.Stderr)
		}()
	}
	return a.readLine(ctx, prompt)
}
