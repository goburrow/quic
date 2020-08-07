package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/goburrow/quic/qlog"
)

func qlogCommand(args []string) error {
	cmd := flag.NewFlagSet("qlog", flag.ExitOnError)
	pretty := cmd.Bool("pretty", false, "pretty print json")
	cmd.Parse(args)

	name := cmd.Arg(0)
	if name == "" {
		fmt.Fprintln(cmd.Output(), "Usage: quince qlog [options] <file>")
		cmd.PrintDefaults()
		return nil
	}
	in, err := os.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()
	data, err := qlog.Decode(in)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	if *pretty {
		enc.SetIndent("", "\t")
	}
	return enc.Encode(data)
}
