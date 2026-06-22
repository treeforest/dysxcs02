package sdf

import (
	"testing"
)

func TestErrOK(t *testing.T) {
	if err := Err(RVOK); err != nil {
		t.Fatalf("RVOK should return nil, got %v", err)
	}
}

func TestErrNonOK(t *testing.T) {
	err := Err(RVKeyNotExist)
	if err == nil {
		t.Fatal("expected error")
	}
	e, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T", err)
	}
	if e.Code != RVKeyNotExist {
		t.Fatalf("code = %v, want %v", e.Code, RVKeyNotExist)
	}
}

func TestRVString(t *testing.T) {
	cases := []struct {
		rv   RV
		want string
	}{
		{RVOK, "SDR_OK"},
		{RVKeyNotExist, "SDR_KEYNOTEXIST"},
		{RVBufferTooSmall, "SDR_BUFFER_TOO_SMALL"},
		{RV(0xDEADBEEF), "SDR_UNKNOWN_0xdeadbeef"},
	}
	for _, tc := range cases {
		if got := tc.rv.String(); got != tc.want {
			t.Errorf("RV(%#x).String() = %q, want %q", uint32(tc.rv), got, tc.want)
		}
	}
}

func TestErrorMessage(t *testing.T) {
	err := Err(RVCommFail)
	if err.Error() != "sdf: SDR_COMMFAIL (0x01000003)" {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
}
