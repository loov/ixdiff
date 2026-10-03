//go:build mulx

#include "textflag.h"

// func mul64(a, b uint64) (hi, lo uint64)
TEXT ·mul64(SB), NOSPLIT, $0-32
	MOVQ  a+0(FP), DX
	MOVQ  b+8(FP), R8
	MULXQ R8, R11, R10
	MOVQ  R10, hi+16(FP)
	MOVQ  R11, lo+24(FP)
	RET
