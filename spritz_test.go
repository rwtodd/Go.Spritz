package spritz

import (
	"bytes"
	"testing"
)

// TestHash tests the 256-bit hash on the three test vecors
// in the RC14.pdf paper defining spritz.
func TestHash(t *testing.T) {
	ansABC := []byte{0x02, 0x8f, 0xa2, 0xb4, 0x8b, 0x93, 0x4a, 0x18}
	ansspam := []byte{0xac, 0xbb, 0xa0, 0x81, 0x3f, 0x30, 0x0d, 0x3a}
	ansarcfour := []byte{0xff, 0x8c, 0xf2, 0x68, 0x09, 0x4c, 0x87, 0xb9}

	oABC := Sum(256, []byte("ABC"))[:8]
	if !bytes.Equal(oABC, ansABC) {
		t.Fatalf("ABC hashed to %x instead of %x", oABC, ansABC)
	}

	ospam := Sum(256, []byte("spam"))[:8]
	if !bytes.Equal(ospam, ansspam) {
		t.Fatalf("spam hashed to %x instead of %x", ospam, ansspam)
	}

	oarcfour := Sum(256, []byte("arcfour"))[:8]
	if !bytes.Equal(oarcfour, ansarcfour) {
		t.Fatalf("arcfour hashed to %x instead of %x", oarcfour, ansarcfour)
	}
}
