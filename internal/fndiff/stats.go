package fndiff

// OpCount is an instruction-mnemonic histogram. Keys are mnemonics
// like "CALL", values are occurrence counts.
type OpCount map[string]int

// CountOps builds a histogram of the mnemonics of ops.
func CountOps(ops []string) OpCount {
	counts := make(OpCount, 64)
	for _, op := range ops {
		counts[op]++
	}
	return counts
}

// Delta returns new minus old per mnemonic, omitting zero entries.
func (old OpCount) Delta(new OpCount) OpCount {
	delta := OpCount{}
	for op, n := range new {
		if d := n - old[op]; d != 0 {
			delta[op] = d
		}
	}
	for op, n := range old {
		if _, ok := new[op]; !ok {
			delta[op] = -n
		}
	}
	return delta
}

// Add accumulates other into the receiver.
func (c OpCount) Add(other OpCount) {
	for op, n := range other {
		c[op] += n
	}
}

// Compact removes zero entries, which appear when accumulated deltas
// cancel out.
func (c OpCount) Compact() {
	for op, n := range c {
		if n == 0 {
			delete(c, op)
		}
	}
}

// Total returns the sum of all counts.
func (c OpCount) Total() int {
	total := 0
	for _, n := range c {
		total += n
	}
	return total
}
