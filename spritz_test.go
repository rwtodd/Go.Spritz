package spritz

import (
	"bytes"
	"compress/zlib"
	"io"
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

// TestReadWrite ensures that the code can decrypt bytes that it just
// encrypted.
func TestReadWrite(t *testing.T) {
}

// TestReadKnown ensures that the code can decrypt a known good message
func TestReadKnown(t *testing.T) {

   testFile := []byte{
         0x21, 0x01, 0x9b, 0x59, 0xaa, 0x4f, 0x76, 0x12,
         0xa2, 0x6a, 0xd4, 0x8b, 0x8d, 0x3f, 0xc2, 0xb9,
         0xeb, 0xa5, 0x31, 0x8f, 0xd8, 0xe1, 0x01, 0x6b,
         0xc7, 0x1a, 0x1c, 0x5f, 0xab, 0xf9, 0xf6, 0xab,
         0x6d, 0x81, 0x1b, 0x14, 0x04, 0x6b, 0x62, 0x6f,
         0xce, 0xaa, 0x2a, 0xb7, 0xb4, 0xd8, 0xed, 0xbf,
         0x49, 0x7c, 0xd0, 0x00, 0xa2, 0x91, 0x30, 0x91,
         0xda, 0x7f, 0x3e, 0xd2, 0xd4, 0xda, 0x56, 0xf4,
         0x50, 0x21, 0x63, 0x99, 0x4c, 0x58, 0x54, 0xb9,
         0xee, 0x1a, 0xf4, 0x5e, 0x6e, 0xcc, 0x63, 0xd1,
         0xab, 0xc4, 0xb3, 0xf3, 0x2a, 0x7e, 0xbd, 0x5d,
         0x6e, 0x9a, 0xcb, 0xba, 0xd9, 0x47, 0x7e, 0xa4,
         0x23, 0x18, 0xb4, 0xfc, 0x8d, 0x01, 0x27, 0x7d,
         0x00, 0x00, 0xd8, 0x37, 0x7b,
   }
   inbuf := bytes.NewBuffer(testFile)
   rdr, decn, err := WrapReader(inbuf, "1234")
   if err != nil {
      t.Fatalf("Error wrapping reader: %v", err)
   } 

   if decn != "tfile.txt" {
      t.Fatalf("Bad original filename <%s>",decn) 
   }

   decomp, err := zlib.NewReader(rdr)
   if err != nil {
      t.Fatalf("Error decompressing reader: %v", err)
   }
   defer decomp.Close()
   var outbuf bytes.Buffer

   if  _,err = io.Copy(&outbuf, decomp);  err != nil {
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
   if  _, err = outbuf.ReadString('\n') ; err != io.EOF {
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
