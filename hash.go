package spritz // import "go.waywardcode.com/spritz"

import "hash"

// Hash provides the hash.Hash interface, consistent with the
// standard packages.
type sphash struct {
	spritzState state
	size        int
}

// NewHash creates a properly-initialized Hash
// with the number of bits of security desired
// (e.g. 256-bit hash, 512-bit hash).
func NewHash(bits int) hash.Hash {
	ans := &sphash{size: ((bits + 7) / 8)}
	initialize(&ans.spritzState)
	return ans
}

// Write absorbs data into the spritz sponge.
func (h *sphash) Write(p []byte) (n int, err error) {
	absorbMany(&h.spritzState, p)
	return len(p), nil
}

// Sum generates the hash based on the data absorbed
// so far. It is possible to then continue feeding
// the hash and generate additional sums.
func (h *sphash) Sum(b []byte) []byte {
	// Make a copy of the internal state so that the caller
	// can keep writing and summing.
	state := h.spritzState

	absorbStop(&state)
	absorb(&state, byte(h.size))
        if state.a > 0 {
           shuffle(&state)
        }
	for idx := 0; idx < h.size; idx++ {
		b = append(b, drip(&state))
	}
	return b
}

// Reset puts the hash in a known initial state, so
// that it can be re-used on another dataset.
func (h *sphash) Reset() {
	initialize(&h.spritzState)
}

// Size gives the size of the computed hash, in bytes.
func (h *sphash) Size() int { return h.size }

// BlockSize is not relevant for spritz, so this method
// returns 1.
func (h *sphash) BlockSize() int { return 1 }

// Sum returns the hash of the given data, sized to
// the given number of bits.
func Sum(bits int, data []byte) []byte {
	h := NewHash(bits)
	h.Write(data)
	return h.Sum(make([]byte, 0, h.Size()))
}
