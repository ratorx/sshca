package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// CommaSeparatedList represents a comma-separated list passed into the command
// line.
type CommaSeparatedList struct {
	Items []string
}

// UnmarshalText converts the bytes received on the command line into a
// CommaSeparatedList
func (csl *CommaSeparatedList) UnmarshalText(b []byte) error {
	csl.Items = strings.Split(string(b), ",")
	return nil
}

func appendIfNotPresent(filename string, toAppend []byte) error {
	contents, _ := ioutil.ReadFile(filename)

	if bytes.Contains(contents, toAppend) {
		return nil
	}

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("unable to open %s for appending: %w", filename, err)
	}

	_, err = f.Write(toAppend)
	if err != nil {
		return fmt.Errorf("failed to append to %s: %w", filename, err)
	}

	return nil
}
