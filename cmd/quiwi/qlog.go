package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/goburrow/quic/qlog"
)

type qlogCommand struct{}

func (qlogCommand) Name() string {
	return "qlog"
}

func (qlogCommand) Desc() string {
	return "transform quiwi logs to qlog format."
}

func (qlogCommand) Run(args []string) error {
	cmd := flag.NewFlagSet("qlog", flag.ExitOnError)
	pretty := cmd.Bool("pretty", false, "pretty print json")
	cmd.Parse(args)

	name := cmd.Arg(0)
	if name == "" {
		fmt.Fprintln(cmd.Output(), "Usage: quiwi qlog [arguments] <file>")
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
	return enc.Encode(&data)
}

func qlogTransformFile(f *os.File) error {
	_, err := f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	data, err := qlog.Decode(f)
	if err != nil {
		return err
	}
	err = f.Truncate(0)
	if err != nil {
		return err
	}
	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	return enc.Encode(&data)
}

type qlogWriter struct {
	path   string
	prefix string
	reader *io.PipeReader
	writer *io.PipeWriter
	// Single file mode
	file *os.File
	// Multile files (Directory) mode
	files  map[string]*os.File
	closed chan struct{}
}

func newQLogWriter(qlogPath, prefix string) (*qlogWriter, error) {
	r, w := io.Pipe()
	s := &qlogWriter{
		path:   path.Clean(qlogPath),
		prefix: prefix,
		reader: r,
		writer: w,
		closed: make(chan struct{}),
	}
	info, err := os.Stat(s.path)
	if err == nil && info.IsDir() {
		// Multiple files
		s.files = make(map[string]*os.File)
	} else {
		// Single file
		s.file, err = os.Create(s.path)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *qlogWriter) Write(b []byte) (int, error) {
	return s.writer.Write(b)
}

func (s *qlogWriter) process() {
	defer close(s.closed)
	if s.file == nil {
		reader := bufio.NewReader(s.reader)
		for {
			line, err := reader.ReadSlice('\n')
			if len(line) > 0 {
				s.handleTrace(line)
			}
			if err != nil {
				if err != io.ErrClosedPipe {
					log.Printf("qlog read: %v", err)
				}
				return
			}
		}
	} else {
		// Write to file and transform to qlog format later.
		s.file.ReadFrom(s.reader)
	}
}

func (s *qlogWriter) handleTrace(b []byte) {
	const cidField = " cid="
	cidIdx := bytes.Index(b, []byte(cidField))
	if cidIdx <= 0 {
		return
	}
	cidIdx += len(cidField)
	sepIdx := bytes.IndexByte(b[cidIdx:], ' ')
	if sepIdx <= 0 {
		return
	}
	cid := string(b[cidIdx : cidIdx+sepIdx])
	f := s.files[cid]
	if f == nil {
		name := filepath.Join(s.path, s.prefix+cid+".qlog")
		var err error
		f, err = os.Create(name)
		if err != nil {
			log.Printf("qlog create file: %v %v", name, err)
			return
		}
		s.files[cid] = f
	}
	_, err := f.Write(b)
	if err != nil {
		log.Printf("qlog write file: %v %v", f.Name(), err)
		delete(s.files, cid)
		f.Close()
		return
	}
	if bytes.Contains(b, []byte("connectivity:connection_closed")) {
		delete(s.files, cid)
		err = qlogTransformFile(f)
		if err != nil {
			log.Printf("qlog transform file: %v %v", f.Name(), err)
		}
		f.Close()
	}
}

func (s *qlogWriter) Close() error {
	s.writer.Close()
	s.reader.Close()
	select {
	case <-s.closed:
	case <-time.After(10 * time.Second):
		return fmt.Errorf("closing qlog writer timed out")
	}
	var closeErr error
	for _, f := range s.files {
		err := qlogTransformFile(f)
		if closeErr == nil {
			closeErr = err
		}
		err = f.Close()
		if closeErr == nil {
			closeErr = err
		}
	}
	if s.file != nil {
		if !strings.HasSuffix(s.path, ".txt") {
			err := qlogTransformFile(s.file)
			if closeErr == nil {
				closeErr = err
			}
		}
		err := s.file.Close()
		if closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}
