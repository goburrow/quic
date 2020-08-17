package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	return qlogTransform(os.Stdout, in, *pretty)
}

func qlogTransform(w io.Writer, r io.Reader, pretty bool) error {
	data, err := qlog.Decode(r)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	if pretty {
		enc.SetIndent("", "\t")
	}
	return enc.Encode(data)
}

func qlogTransformToFile(name string, r io.Reader) error {
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return qlogTransform(f, r, false)
}
