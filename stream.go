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
	"os"

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

// hash and re-hash the same data a few times during keygen
// N.B.: it destroys the IV ...
func keygen(pw string, iv []byte, times int) []byte {
	ans := Sum(512, []byte(pw))
	cipher := new(state)

	for idx := 0; idx < times; idx++ {
		initialize(cipher)
		absorbMany(cipher, iv)
		iv[0] = byte(iv[0] + 1)
		if iv[0] == 0 {
			iv[1] = byte(iv[1] + 1)
			if iv[1] == 0 {
				iv[2] = byte(iv[2] + 1)
				if iv[2] == 0 {
					iv[3] = byte(iv[3] + 1)
				}
			}
		}
		absorbStop(cipher)
		absorbMany(cipher, ans)
		dripMany(cipher, ans)
	}

	return ans
}

// reads enough to get the "real" key out of the encrypted
// stream
func readHeader(src io.Reader, pw string) (realKey []byte, err error) {
	iv := make([]byte, 4)
	if _, err = io.ReadFull(src, iv); err != nil {
		return
	}

	// Stage 1... IV is encrypted against hashed pw...
	tmp32 := Sum(32, []byte(pw))
	xorInto(iv, tmp32) // decrypt IV

	// Stage 2... generate a key from the pw + IV...
	key := keygen(pw, iv, 20000+int(iv[3]))
	crypto := new(state)
	initialize(crypto)
	absorbMany(crypto, key)

	// Stage 3... check the password...
	rdr := &cipher.StreamReader{S: crypto, R: src}

	// decrypt random bytes
	rbytes := make([]byte, 4)
	if _, err = io.ReadFull(rdr, rbytes); err != nil {
		return
	}

	// skip the number stream bytes equal to rbytes[3]
	if crypto.a > 0 {
		shuffle(crypto)
	}
	for skip := 0; skip < int(rbytes[3]); skip++ {
		drip(crypto)
	}

	// decrypt the hash of rbytes
	remaining := make([]byte, 4)
	if _, err = io.ReadFull(rdr, remaining); err != nil {
		return
	}

	// check the hash match
	if !bytes.Equal(remaining, Sum(32, rbytes)) {
		err = fmt.Errorf("Bad pw or corrupted file!")
		return
	}

	// Stage 4... get the real key
	realKey = make([]byte, 64)
	if _, err = io.ReadFull(rdr, realKey); err != nil {
		return
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
func WrapReader(src io.Reader, pw string) (rdr io.Reader, fn string, err error) {
	var realKey []byte
	realKey, err = readHeader(src, pw)
	if err != nil {
		return
	}
	crypto := new(state)
	initialize(crypto)
	absorbMany(crypto, realKey)
	if crypto.a > 0 { // RWT LATER l8r
		shuffle(crypto)
	}

	// skip the number stream bytes equal to realKey[3] + 2048
	for skip := 0; skip < (2048 + int(realKey[3])); skip++ {
		// RWT put back: drip(crypto)
		fmt.Printf("Dripped %d: %02X\r\n", skip, drip(crypto))
	}
	rdr = &cipher.StreamReader{S: crypto, R: src}

	// get the filename, if any, from the file:
	flen := make([]byte, 1)
	if _, err = io.ReadFull(rdr, flen); err != nil {
		return
	}
	if flen[0] > 0 {
		decnBytes := make([]byte, flen[0])
		if _, err = io.ReadFull(rdr, decnBytes); err != nil {
			return
		}
		fn = string(decnBytes)
	}

	return
}

func xorInto(dst, src []byte) {
	if len(dst) < len(src) {
		panic("Bad args to xorInto!")
	}
	for idx, v := range src {
		dst[idx] = dst[idx] ^ v
	}

}

func writeHeader(sink io.Writer, pw string, realKey []byte) error {
	var iv = make([]byte, 4)
	var err1 error
	if _, err1 = rand.Read(iv); err1 != nil {
		return err1
	}

	encIV := Sum(32, []byte(pw))
	xorInto(encIV, iv)
	sink.Write(encIV) // write the manually-encrypted IV

	key := keygen(pw, iv, 20000+int(iv[3]))
	crypto := new(state)
	initialize(crypto)
	absorbMany(crypto, key)

	// let the writer encrypt everything from here on out..
	writer := &cipher.StreamWriter{S: crypto, W: sink}

	var rbytes = make([]byte, 4)
	if _, err1 = rand.Read(rbytes); err1 != nil {
		return err1
	}

	lastbyte := int(rbytes[3])
	var rbhash = Sum(32, rbytes)

	// write rbytes, then skip lastbyte stream bytes, then
	// write the version and the hashed rbytes
	_, err1 = writer.Write(rbytes)

	// skip the number stream bytes equal to rbytes[3]
	if crypto.a > 0 {
		shuffle(crypto)
	}
	for skip := 0; skip < lastbyte; skip++ {
		drip(crypto)
	}

	_, err2 := writer.Write(rbhash)
	_, err3 := writer.Write(realKey)

	return errs.First("Writing encryption header", err1, err2, err3)
}

// WrapWriter wraps a writer with an encrypting
// stream, using an IV/Password, data used to check
// that the password appears correct, and an optional
// stored original filename of the source data.  All of
// this is stored in a format that agrees with the
// expectations of WrapReader, and is just an example of
// how one may turn the encryption stream into a file format.
func WrapWriter(sink io.Writer, pw string, origfn string) (io.Writer, error) {
	var realKey = make([]byte, 64)
	var err1 error
	if _, err1 = rand.Read(realKey); err1 != nil {
		return nil, err1
	}

	if err1 = writeHeader(sink, pw, realKey); err1 != nil {
		return nil, err1
	}

	crypto := new(state)
	initialize(crypto)
	absorbMany(crypto, realKey)
	if crypto.a > 0 {
		shuffle(crypto)
	}
	// skip the number stream bytes equal to realKey[3] + 2048
	for skip := 0; skip < (2048 + int(realKey[3])); skip++ {
		drip(crypto)
	}
	writer := &cipher.StreamWriter{S: crypto, W: sink}

	var namebytes []byte
	namebytes = append(namebytes, byte(len(origfn)))
	namebytes = append(namebytes, []byte(origfn)...)
	_, err2 := writer.Write(namebytes)

	return writer, errs.Wrap("Writing encryption header", err2)
}

// change the password on a given file, without
// re-encrypting the whole contents
func RePasswd(oldpw, newpw, fn string) error {
	fl, err := os.OpenFile(fn, os.O_RDWR, 0666)
	defer fl.Close()

	if err != nil {
		return err
	}

	realKey, err := readHeader(fl, oldpw)
	if err != nil {
		return err
	}

	_, err = fl.Seek(0, os.SEEK_SET)
	if err != nil {
		return err
	}

	err = writeHeader(fl, newpw, realKey)

	return err
}
