package sshd

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Lookup key in the effective SSHD config. This doesn't search the config path.
// Instead it uses sshd -T to get the values of default paramters too.
func Lookup(configPath string, key string) ([]string, error) {
	out, _, err := checkedRun(exec.Command("sshd", "-T", "-f", configPath))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch effective config: %w", err)
	}

	// sshd -T prints out lowercase options
	key = strings.ToLower(key)

	lineRegexp := regexp.MustCompile(fmt.Sprintf("(?m)^%s (.*)$", regexp.QuoteMeta(key)))
	values := lineRegexp.FindAllSubmatch(out, -1)
	ret := make([]string, 0, len(values))
	for _, value := range values {
		ret = append(ret, string(value[1]))
	}

	return ret, nil
}