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
	if s.a > 0 {
		shuffle(s)
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
	crypto := new(state)
	initialize(crypto)
	if len(iv) > 0 {
		absorbMany(crypto, iv)
		absorbStop(crypto)
	}
	absorbMany(crypto, Sum(1024, []byte(password)))
	keyBytes := make([]byte, 128)
	dripMany(crypto, keyBytes)

	for idx := 0; idx < 5000; idx++ {
		initialize(crypto)
		absorbMany(crypto, keyBytes)
		absorbStop(crypto)
		absorb(crypto, 128)
		dripMany(crypto, keyBytes)
	}

	initialize(crypto)
	absorbMany(crypto, keyBytes)
	return crypto
}
