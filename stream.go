package spritz

// ---------------------------------------
// provide a Stream cipher interface
// consistent with the standard golang
// packages
// ---------------------------------------

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/rwtodd/errs-go"
)

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

// WrapReader wraps an io.Reader with a decrypting
// stream, using an IV/Password, a check that the
// password appears correct, and an optional stored
// filename of the encrypted data.  All of this is
// in a format that agrees with the output of
// WrapWriter, and is just an example of how one may
// turn the encryption stream into a file format.
func WrapReader(src io.Reader, pw string) (rdr io.Reader, fn string, err error) {
	header := make([]byte, 5)
	if _, err = io.ReadFull(src, header); err != nil {
		return
	}

	// check the first byte...
	if header[0] != 1 {
		return
	}

	rdr = &cipher.StreamReader{S: NewStream(pw, header[1:]), R: src}

	encheader := make([]byte, 9)
	if _, err = io.ReadFull(rdr, encheader); err != nil {
		return
	}

	check := Sum(32, encheader[0:4])
	if !bytes.Equal(check, encheader[4:8]) {
		err = fmt.Errorf("Bad password or corrupted file!")
		return
	}

	// input looks good, so set up the output
	// get the filename, if any, from the file:
	if encheader[8] > 0 {
		decnBytes := make([]byte, encheader[8])
		if _, err = io.ReadFull(rdr, decnBytes); err != nil {
			return
		}
		fn = string(decnBytes)
	}

	return
}

// WrapWriter wraps a writer with an encrypting
// stream, using an IV/Password, data used to check
// that the password appears correct, and an optional
// stored original filename of the source data.  All of
// this is stored in a format that agrees with the
// expectations of WrapReader, and is just an example of
// how one may turn the encryption stream into a file format.
func WrapWriter(sink io.Writer, pw string, origfn string) (io.Writer, error) {
	// we need random data for the IV and authentication token
	var header = make([]byte, 9)
	header[0] = 1
	_, err1 := rand.Read(header[1:])

	var namebytes []byte
	namebytes = append(namebytes, byte(len(origfn)))
	namebytes = append(namebytes, []byte(origfn)...)

	sink.Write([]byte{1})   // write output version number
	sink.Write(header[1:5]) // write the IV unencrypted!

	writer := &cipher.StreamWriter{S: NewStream(pw, header[1:5]), W: sink}
	_, err2 := writer.Write(header[5:])           // write the authentication token
	_, err3 := writer.Write(Sum(32, header[5:])) // write the hash of the token
	_, err4 := writer.Write(namebytes)

	return writer, errs.First("Writing encryption header", err1, err2, err3, err4) 
}
