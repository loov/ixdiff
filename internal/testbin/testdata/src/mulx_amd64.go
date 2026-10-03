//go:build mulx

package main

import "os"

// mul64 returns the 128-bit product of a and b. It is written in
// assembly around a VEX-encoded MULXQ so tests can check that VEX
// instructions decode in step with the code; the compiler only emits
// MULXQ for some code shapes, and not on every toolchain.
func mul64(a, b uint64) (hi, lo uint64)

func init() {
	if os.Getenv("IXDIFF_MULX") == "run" {
		println(mul64(uint64(len(os.Args)), 3))
	}
}
