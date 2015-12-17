package spritz

// ------------------------------------------------------
// Provide a hashing interface, consistent with the
// standard packages
// ------------------------------------------------------

type Hash struct {
	spritzState state
	size        int
}

func NewHash(bits int) *Hash {
	ans := &Hash{size: ((bits + 7) / 8)}
	initialize(&ans.spritzState)
	return ans
}

func (h *Hash) Write(p []byte) (n int, err error) {
	absorbMany(&h.spritzState, p)
	return len(p), nil
}

func (h *Hash) Sum(b []byte) []byte {
	// Make a copy of the internal state so that the caller
	// can keep writing and summing.
	state := h.spritzState

	absorbStop(&state)
	absorb(&state, byte(h.size))
	for idx := 0; idx < h.size; idx++ {
		b = append(b, drip(&state))
	}
	return b
}

func (h *Hash) Reset() {
	initialize(&h.spritzState)
}

func (h *Hash) Size() int { return h.size }

func (h *Hash) BlockSize() int { return 1 }

// Sum returns the hash of the given data.
func Sum(bits int, data []byte) []byte {
	h := NewHash(bits)
	h.Write(data)
	return h.Sum(make([]byte, 0, h.size))
}
