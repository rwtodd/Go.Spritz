// Spritz provides the sponge-like streaming
// cipher described in https://people.csail.mit.edu/rivest/pubs/RS14.pdf
//
// This package provides an implementation of hash.Hash as well as
// cipher.Stream.  Therefore, spritz will be easy to use if you are
// familiar with the way the standard hashes and ciphers work.
package spritz

// nothing in this file is public... it is the internal machinery
// driving the hash and stream implementations in the other files.

type state struct {
	i, j, k, z, a, w byte
	s                [256]byte
}

func initialize(s *state) {
	s.w = 1
	for i := range s.s {
		s.s[i] = byte(i)
	}
}

func absorb(ss *state, b byte) {
	absorbNibble(ss, b&0x0F)
	absorbNibble(ss, b>>4)
}

func absorbMany(ss *state, bs []byte) {
	for _, b := range bs {
		absorbNibble(ss, b&0x0F)
		absorbNibble(ss, b>>4)
	}
}

func swap(arr *[256]byte, e1 int, e2 int) {
	arr[e1], arr[e2] = arr[e2], arr[e1]
}

func absorbNibble(ss *state, x byte) {
	if ss.a == 256/2 {
		shuffle(ss)
	}
	swap(&ss.s, int(ss.a), int(256/2+x))
	ss.a++
}

func absorbStop(ss *state) {
	if ss.a == 256/2 {
		shuffle(ss)
	}
	ss.a++
}

func whip(ss *state) {
	update(ss, 512)
	ss.w++
	if ss.w&1 == 0 {
		ss.w++
	}
}

func crush(ss *state) {
	for v := 0; v < 128; v++ {
		if ss.s[v] > ss.s[256-1-v] {
			swap(&ss.s, v, 256-1-v)
		}
	}
}

func shuffle(ss *state) {
	whip(ss)
	crush(ss)
	whip(ss)
	crush(ss)
	whip(ss)
	ss.a = 0
}

func update(ss *state, amt int) {
	// make local copies of the variables
	// because it helps the optimizer
	var mi byte = ss.i
	var mj byte = ss.j
	var mk byte = ss.k
	var mw byte = ss.w

	for amt > 0 {
		mi += mw
		smi := ss.s[mi]
		mj = mk + ss.s[mj+smi]
		smj := ss.s[mj]
		mk = mi + mk + smj
		ss.s[mi] = smj
		ss.s[mj] = smi
		amt--
	}

	// store the final values of the locals
	// saved at the top of the function
	ss.i = mi
	ss.j = mj
	ss.k = mk
}

func drip(ss *state) byte {
	if ss.a > 0 {
		shuffle(ss)
	}
	update(ss, 1)
	ss.z = ss.s[ss.j+ss.s[ss.i+ss.s[ss.z+ss.k]]]
	return ss.z
}

func dripMany(ss *state, bs []byte) {
	for idx := range bs {
		bs[idx] = drip(ss)
	}
}
