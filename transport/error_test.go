package transport

import (
	"fmt"
	"testing"
)

func TestErrorFormat(t *testing.T) {
	data := []struct {
		code uint64
		msg  string
		err  string
	}{
		{1, "no idea", "internal_error no idea"},
		{12, "", "application_error"},
		{0x100, "general", "crypto_error general"},
		{0x1ff, "", "crypto_error_255"},
		{0xffff, "unknown", "65535 unknown"},
	}
	for _, d := range data {
		err := newError(d.code, d.msg)
		if err.Error() != d.err {
			t.Errorf("expect error %v, actual: %v", d.err, err)
		}
	}
}

func TestSprint(t *testing.T) {
	s := sprint("xyz", int64(100), " ", true, uint64(2000), "^abc$", []byte("12345"), ".", []uint32{99, 98})
	if s != "xyz100 true2000^abc$3132333435.[99,98]" {
		t.Fatalf("sprint: %v", s)
	}
}

func BenchmarkSprint(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := sprint(int64(1234567890), " 1234567890 ", false, "/", []byte("1234567890"), []uint32{1, 2, 3})
		if s != "1234567890 1234567890 false/31323334353637383930[1,2,3]" {
			b.Fatalf("sprint %v", s)
		}
	}
}

func BenchmarkFmtSprint(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := fmt.Sprint(int64(1234567890), " 1234567890 ", false, "/", []byte("1234567890"), []uint32{1, 2, 3})
		if s != "1234567890 1234567890 false/[49 50 51 52 53 54 55 56 57 48] [1 2 3]" {
			b.Fatalf("fmt.Sprint %v", s)
		}
	}
}
