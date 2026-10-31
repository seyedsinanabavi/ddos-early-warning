package signals

import (
	"strings"
	"testing"
)

const procTCPSample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234
   1: 0100007F:1F90 0100007F:D2F4 01 00000000:00000000 00:00000000 00000000     0        0 1235
   2: 0100007F:1F90 0100007F:D2F5 01 00000000:00000000 00:00000000 00000000     0        0 1236
   3: 0100007F:1F90 0100007F:D2F6 03 00000000:00000000 00:00000000 00000000     0        0 1237
`

func TestCountTCPStates(t *testing.T) {
	var c TCPCounts
	if err := countTCPStates(strings.NewReader(procTCPSample), &c); err != nil {
		t.Fatal(err)
	}
	if c.Established != 2 || c.SynRecv != 1 {
		t.Fatalf("got %+v want established=2 syn_recv=1", c)
	}
}

func TestCountTCPStates_HeaderOnlyAndMalformed(t *testing.T) {
	var c TCPCounts
	if err := countTCPStates(strings.NewReader("header\n"), &c); err != nil || c != (TCPCounts{}) {
		t.Fatalf("header only: %+v err=%v", c, err)
	}
	if err := countTCPStates(strings.NewReader("header\n 0: short\n"), &c); err == nil {
		t.Fatal("short row must be an error")
	}
}

func TestProcTCPSource_MissingFile(t *testing.T) {
	src := &ProcTCPSource{Paths: []string{"/definitely/not/here"}}
	if _, err := src.Counts(); err == nil {
		t.Fatal("missing file must be an error")
	}
	if _, err := (&ProcTCPSource{}).Counts(); err == nil {
		t.Fatal("no paths must be an error")
	}
}

func TestStubs_ReturnNotImplemented(t *testing.T) {
	for _, s := range []Signal{SrcEntropy{}, ASNConcentration{}} {
		res, err := s.Eval(cancelledCtx(), window(10, nil), nil)
		if err != ErrNotImplemented {
			t.Fatalf("%s: err=%v", s.Name(), err)
		}
		if !res.Missing || res.Fired {
			t.Fatalf("%s: stub must be missing and not fired", s.Name())
		}
	}
}
