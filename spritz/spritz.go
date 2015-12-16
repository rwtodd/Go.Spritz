package spritz

const (
	N = 256
)

type state struct {
	i, j, k, z, a, w byte
	s                [N]byte
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

func swap(arr *[N]byte, e1 int, e2 int) {
	arr[e1], arr[e2] = arr[e2], arr[e1]
}

func absorbNibble(ss *state, x byte) {
	if ss.a == N/2 {
		shuffle(ss)
	}
	swap(&ss.s, int(ss.a), int(N/2+x))
	ss.a++
}

func absorbStop(ss *state) {
	if ss.a == N/2 {
		shuffle(ss)
	}
	ss.a++
}

func gcd(e1 int, e2 int) int {
	if e2 == 0 {
		return e1
	}
	return gcd(e2, e1%e2)
}

func whip(ss *state) {
	update(ss, N*2)
	ss.w++
	for gcd(int(ss.w), 256) != 1 {
		ss.w++
	}
}

func crush(ss *state) {
	for v := 0; v < (N / 2); v++ {
		if ss.s[v] > ss.s[N-1-v] {
			swap(&ss.s, v, N-1-v)
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
