// Package secret loads the API tokens of configured instances. A token is
// read from a protected file or from an environment variable, is never
// written to a log, and is never part of an error message.
package secret

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxTokenFileSize bounds a token file; real tokens are well under 1 KiB.
const maxTokenFileSize = 16 << 10

// ReadTokenFile returns the trimmed contents of a token file. The file must
// be a regular file (not a symlink) without group or other permissions, in
// a directory that is not group or world writable.
func ReadTokenFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("token_file is required")
	}
	dirInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return "", wrap("inspect token_file directory failed", err)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() || dirInfo.Mode().Perm()&0o022 != 0 {
		return "", errors.New("token_file directory must be a real directory that is not group or world writable")
	}

	pathInfo, err := os.Lstat(path)
	if err != nil {
		return "", wrap("inspect token_file failed", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0o077 != 0 {
		return "", errors.New("token_file must be a regular file with no group or other permissions")
	}

	file, err := os.Open(path)
	if err != nil {
		return "", wrap("open token_file failed", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return "", wrap("inspect opened token_file failed", err)
	}
	if !os.SameFile(pathInfo, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 {
		return "", errors.New("token_file changed while opening")
	}

	contents, err := io.ReadAll(io.LimitReader(file, maxTokenFileSize+1))
	if err != nil {
		return "", wrap("read token_file failed", err)
	}
	if len(contents) > maxTokenFileSize {
		return "", errors.New("token_file exceeds the maximum size")
	}
	token := strings.TrimSpace(string(contents))
	if token == "" {
		return "", errors.New("token_file is empty")
	}
	if err := checkToken(token); err != nil {
		return "", err
	}
	return token, nil
}

// FromEnv returns the token held by the environment variable name. The
// error names the variable, never its value.
func FromEnv(name string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", errors.New("token_env variable " + name + " is not set")
	}
	token := strings.TrimSpace(value)
	if token == "" {
		return "", errors.New("token_env variable " + name + " is empty")
	}
	if err := checkToken(token); err != nil {
		return "", err
	}
	return token, nil
}

// checkToken refuses values that cannot be a header value. net/http would
// reject them later with an error that may quote the value.
func checkToken(token string) error {
	for _, r := range token {
		if r < 0x21 || r > 0x7e {
			return errors.New("the API token contains whitespace, control or non-ASCII characters")
		}
	}
	return nil
}

func wrap(msg string, err error) error {
	return errors.New(msg + ": " + err.Error())
}
