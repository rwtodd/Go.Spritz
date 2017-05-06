package spritz

import (
	"bytes"
	"encoding/base64"
	"io"
	"math/rand"
	"testing"
	"time"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

// TestLargeHashes tests the huge hashes 
// func TestLargeHash(t *testing.T) {
// 	ans1024 := "mODbEBMQN0e4fNQkMpQAFXRnJb+m4qJ4Jj/ZD85JEnqkgx0guarutyDDNUC6kDvDxjoR1jNfDIa8zf6nWNUdypzFTYQwL34Ci/SWcRq78Kzvod+oGZSTvpMuznWPo2nzVY32LPY/CI4E=" // test of arc
// 	ans4096 := "/51nef3y/1tdjXK2VFYoV/gSghU2nsOHLRoGnE" // large-hash
// }

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

// TestReadWrite ensures that the code can decrypt bytes that it just
// encrypted.
func TestReadWrite(t *testing.T) {
	for count := 0; count < 20; count++ {
		// random password
		pwBytes := make([]byte, 15)
		_, _ = rand.Read(pwBytes)
		pw := string(pwBytes)

		// random orig name
		origName := ""
		if rand.Intn(10) < 5 {
			origNameBytes := make([]byte, 10)
			_, _ = rand.Read(origNameBytes)
			origName = string(origNameBytes)
		}

		// random data
		datalen := rand.Intn(2048) + 1
		data := make([]byte, datalen)
		_, _ = rand.Read(data)
		inbuf := bytes.NewBuffer(data)

		// encyrpt!
		var encbuf bytes.Buffer
		wtr, err := WrapWriter(&encbuf, pw, origName)
		if err != nil {
			t.Fatalf("Error wrapping writer: %v", err)
		}

		_, err = io.Copy(wtr, inbuf)
		if err != nil {
			t.Fatalf("Error encrypting: %v", err)
		}

		// decrypt!
		var decbuf bytes.Buffer
		rdr, decn, err := WrapReader(&encbuf, pw)
		if err != nil {
			t.Fatalf("Error wrapping for decryption: %v", err)
		}
		if decn != origName {
			t.Fatalf("Orig names don't match, got <%s> instead of <%s>", decn, origName)
		}

		_, err = io.Copy(&decbuf, rdr)
		if err != nil {
			t.Fatalf("Error decrypting: %v", err)
		}

		if !bytes.Equal(decbuf.Bytes(), data) {
			t.Fatalf("Decrypted data does not match encrypted data!")
		}
	}
}

// TestReadKnown ensures that the code can decrypt a known good message
func TestReadKnown(t *testing.T) {

	testFile := []byte{
		0x96, 0x31, 0x58, 0x44, 0xE8, 0x46, 0xB4, 0xE4,
		0xFF, 0x16, 0xDB, 0xCE, 0xCB, 0x74, 0x31, 0xEF,
		0x6F, 0x03, 0xCD, 0x8C, 0x0C, 0x70, 0x9A, 0x1A,
		0x6F, 0x72, 0x3A, 0xA7, 0x5A, 0xAF, 0x50, 0x0E,
		0xBE, 0xC5, 0xA2, 0x35, 0xF0, 0x7E, 0x82, 0x5C,
		0xF6, 0xBB, 0x2C, 0x74, 0xE9, 0x13, 0x6E, 0xAF,
		0x59, 0x59, 0xD2, 0x86, 0xDF, 0xA4, 0x21, 0xB8,
		0x2B, 0x61, 0xBF, 0x40, 0x45, 0xFE, 0x8F, 0xB0,
		0x67, 0x5E, 0x72, 0xA1, 0x6F, 0x8B, 0xA9, 0x86,
		0xA8, 0x50, 0xA4, 0xE7, 0xB3, 0xE4, 0xE4, 0xC8,
		0xCE, 0x8D, 0x28, 0xDD, 0x36, 0xCA, 0x94, 0x12,
		0x14, 0xFE, 0x51, 0x4C, 0xDD, 0x24, 0xFD, 0x8E,
		0xDD, 0xA1, 0x21, 0x53, 0x6C, 0xCD, 0x07,
	}
	inbuf := bytes.NewBuffer(testFile)
	rdr, decn, err := WrapReader(inbuf, "1234")
	if err != nil {
		t.Fatalf("Error wrapping reader: %v", err)
	}

	if decn != "tfile.txt" {
		t.Fatalf("Bad original filename <%s>", decn)
	}

	var outbuf bytes.Buffer

	if _, err = io.Copy(&outbuf, rdr); err != nil {
		t.Fatalf("Error decrypting: %v", err)
	}

	var line string
	expect := func(answer string) {
		line, err = outbuf.ReadString('\n')
		if (line != answer) || (err != nil) {
			t.Fatalf("Error <%v>: bad decrypted line: <%s> instead of <%s>", err, line, answer)
		}
	}

	expect("abc\n")
	expect("abc\n")
	expect("123\n")
	expect("123\n")
	expect("\n")
	if _, err = outbuf.ReadString('\n'); err != io.EOF {
		t.Fatalf("Error decrypting file.. expected EOF but didn't get it.")
	}

}

// BenchmarkKeygen benchmarks the key generation function, to make sure
// that it is slow enough to deter brute-force attack.
func BenchmarkKeygen(b *testing.B) {
	examplePW := "12345678901234"   // 14-char "good" password
	exampleIV := []byte{4, 3, 2, 1} // a "random" IV

	//func keygen(pw string, iv []byte, times int) []byte {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exampleIV = keygen(examplePW, exampleIV[:4], 20000+int(exampleIV[3]))
	}
}
