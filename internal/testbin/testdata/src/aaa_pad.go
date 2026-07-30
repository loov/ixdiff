//go:build pad

package main

import (
	"fmt"
	"os"
)

// aaaPad exists to shift the layout of every later function without
// changing their bodies; tests use it to check that normalization is
// stable when addresses move. The file sorts before main.go so its
// code is emitted first, and the init reference keeps the linker from
// discarding it.
func aaaPad() {
	for i := 0; i < 100; i++ {
		fmt.Println("padding", i, i*i, i*i*i)
	}
}

func init() {
	if os.Getenv("IXDIFF_PAD") == "run" {
		aaaPad()
	}
}
