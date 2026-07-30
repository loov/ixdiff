// Command fixture is a small program compiled by package testbin to
// produce binaries for tests. It is written so that build flags change
// its generated code in predictable ways: add is small enough to be
// inlined by default and kept as a call under -gcflags=-l.
package main

import (
	"fmt"
	"os"
)

func add(a, b int) int {
	return a + b
}

func sum(xs []int) int {
	total := 0
	for _, x := range xs {
		total = add(total, x)
	}
	return total
}

func main() {
	xs := make([]int, len(os.Args))
	for i := range xs {
		xs[i] = i * 3
	}
	fmt.Println(sum(xs))
}
