package spritz

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

func NewStream(password string, iv []byte) cipher.Stream {
	st := new(state)
	initialize(st)
	key := Sum(256, []byte(password))
	absorbMany(st, key)
	absorbStop(st)
	absorbMany(st, iv)
	return st
}
