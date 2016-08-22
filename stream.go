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

	"github.com/rwtodd/apputil-go/errs"
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
func newStream(password string, iv []byte, iterations int) cipher.Stream {
	crypto := new(state)
	initialize(crypto)
	if len(iv) > 0 {
		absorbMany(crypto, iv)
		absorbStop(crypto)
	}
	absorbMany(crypto, Sum(1024, []byte(password)))
	keyBytes := make([]byte, 128)
	dripMany(crypto, keyBytes)

	for idx := 0; idx < iterations; idx++ {
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

func readV1Header(src io.Reader, pw string) (rdr io.Reader, fn string, err error) {
	iv := make([]byte, 4)
	if _, err = io.ReadFull(src, iv); err != nil {
		return
	}

	var stream = newStream(pw, iv, 5000)

	rdr = &cipher.StreamReader{S: stream, R: src}

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

// hash and re-hash the same data a few times during keygen
func rehashKey(cipher *state, iv []byte, tmp []byte) {
	for idx := 0; idx < 20; idx++ {
		dripMany(cipher, tmp)
		absorbMany(cipher, iv)
		absorbStop(cipher)
		absorbMany(cipher, tmp)
	}
}

// readHeader understands all header types except V1... see
// readV1Header() for that.
func readHeader(src io.Reader, firstByte byte, pw string) (rdr io.Reader, fn string, err error) {
	fmt.Printf("pw is <%s>\n", pw)

	iv := make([]byte, 4)
	iv[0] = firstByte
	if _, err = io.ReadFull(src, iv[1:]); err != nil {
		return
	}

	crypto := new(state)
	initialize(crypto)

	tmp256 := Sum(2048, []byte(pw))
	fmt.Printf("%d\n%02x\n", len(tmp256), tmp256)

	absorbMany(crypto, tmp256)
	absorbStop(crypto)
	absorb(crypto, 4)

	fmt.Printf("before: %02X\n", iv)
	crypto.XORKeyStream(iv, iv) // decrypt IV
	fmt.Printf("after: %02X\n", iv)

	rehashKey(crypto, iv, tmp256)

	rdr = &cipher.StreamReader{S: crypto, R: src}

	// decrypt random bytes
	rbytes := make([]byte, 4)
	if _, err = io.ReadFull(rdr, rbytes); err != nil {
		return
	}

	// skip the number stream bytes equal to rbytes[3]
	for skip := 0; skip < int(rbytes[3]); skip++ {
		drip(crypto)
	}

	// decrypt the version number, hash of rbytes, and fname len...
	remaining := make([]byte, 6)
	if _, err = io.ReadFull(rdr, remaining); err != nil {
		return
	}

	// check the version number and hash match
	if (remaining[0] != 2) ||
		(!bytes.Equal(remaining[1:5], Sum(32, rbytes))) {
		err = fmt.Errorf("Bad pw or corrupted file! %02X vs %02X vers %d",
			remaining[1:5], Sum(32, rbytes), remaining[0])
		return
	}

	// input looks good, so set up the output
	// get the filename, if any, from the file:
	if remaining[5] > 0 {
		decnBytes := make([]byte, remaining[5])
		if _, err = io.ReadFull(rdr, decnBytes); err != nil {
			return
		}
		fn = string(decnBytes)
	}

	return
}

// WrapReader wraps an io.Reader with a decrypting
// stream, using an IV/Password, a check that the
// password appears correct, and an optional stored
// filename of the encrypted data.  All of this is
// in a format that agrees with the output of
// WrapWriter, and is just an example of how one may
// turn the encryption stream into a file format.
func WrapReader(src io.Reader, pw string) (io.Reader, string, error) {
	header := make([]byte, 1)
	if _, err := io.ReadFull(src, header); err != nil {
		return nil, "", err
	}

	// check the first byte for the version number
	switch header[0] {
	case 1:
		return readV1Header(src, pw)
	default:
		return readHeader(src, header[0], pw)
	}

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

	writer := &cipher.StreamWriter{S: newStream(pw, header[1:5], 5000), W: sink}
	_, err2 := writer.Write(header[5:])          // write the authentication token
	_, err3 := writer.Write(Sum(32, header[5:])) // write the hash of the token
	_, err4 := writer.Write(namebytes)

	return writer, errs.First("Writing encryption header", err1, err2, err3, err4)
}
