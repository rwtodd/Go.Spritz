package spritz_go

// ---------------------------------------
// provide a Stream cipher interface
// consistent with the standard golang
// packages
// ---------------------------------------

import "crypto/cipher"

func (s *state) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("Bad args to XORKeyStream!")
	}
	for idx, v := range src {
		dst[idx] = v ^ drip(s)
	}
}

// NewStream creates a cipher.Stream instance for
// a spritz cipher primed with a password and an
// initialization vector.
//
// The password string will be hashed to 256-bits, and the
// initialization vector can be as long as desired.
func NewStream(password string, iv []byte) cipher.Stream {
	st := new(state)
	initialize(st)
	key := Sum(256, []byte(password))
	absorbMany(st, key)
	absorbStop(st)
	absorbMany(st, iv)
	return st
}
