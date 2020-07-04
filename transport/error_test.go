package transport

import "testing"

func TestErrorFormat(t *testing.T) {
	data := []struct {
		code uint64
		msg  string
		err  string
	}{
		{1, "no idea", "INTERNAL_ERROR no idea"},
		{12, "", "APPLICATION_ERROR"},
		{0x100, "general", "CRYPTO_ERROR general"},
		{0x1ff, "", "CRYPTO_ERROR 255"},
		{0xffff, "unknown", "0xffff unknown"},
	}
	for _, d := range data {
		err := Error{d.code, d.msg}
		if err.Error() != d.err {
			t.Errorf("unexpect error string: %+v %q", err, err.Error())
		}
	}
}
