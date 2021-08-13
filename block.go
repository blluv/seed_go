package seedgo

func char2word(c []byte, off uint32) uint32 {
	return uint32(c[off])<<24 | uint32(c[off+1])<<16 | uint32(c[off+2])<<8 | uint32(c[off+3])
}

func word2char(in uint32, out []byte, off uint32) {
	out[off] = byte(in >> 24)
	out[off+1] = byte(in >> 16)
	out[off+2] = byte(in >> 8)
	out[off+3] = byte(in)
}

func g_func(val uint32) uint32 {
	return SS[0][val&0xff] ^ SS[1][val>>8&0xff] ^ SS[2][val>>16&0xff] ^ SS[3][val>>24&0xff]
}

func roundKeyUpdate0(K []uint32, A, B, C, D *uint32, Z uint32, off uint32) {
	T0 := *A + *C - KC[Z]
	T1 := *B + KC[Z] - *D
	K[off+0] = g_func(T0)
	K[off+1] = g_func(T1)
	T0 = *A
	*A = (*A >> 8) ^ (*B << 24)
	*B = (*B >> 8) ^ (T0 << 24)
}

func roundKeyUpdate1(K []uint32, A, B, C, D *uint32, Z uint32, off uint32) {
	T0 := *A + *C - KC[Z]
	T1 := *B + KC[Z] - *D
	K[off+0] = g_func(T0)
	K[off+1] = g_func(T1)
	T0 = *C
	*C = (*C << 8) ^ (*D >> 24)
	*D = (*D << 8) ^ (T0 >> 24)
}

func seedRound(L0, L1, R0, R1 *uint32, K []uint32, off uint32) {
	T0 := *R0 ^ K[off+0]
	T1 := *R1 ^ K[off+1]
	T1 ^= T0
	T1 = g_func(T1)
	T0 += T1
	T0 = g_func(T0)
	T1 += T0
	T1 = g_func(T1)
	T0 += T1
	*L0 ^= T0
	*L1 ^= T1
}

func seedRoundKey(userKey []byte, roundKey []uint32) {
	var A uint32
	var B uint32
	var C uint32
	var D uint32

	A = char2word(userKey, 0)
	B = char2word(userKey, 4)
	C = char2word(userKey, 8)
	D = char2word(userKey, 12)

	roundKeyUpdate0(roundKey, &A, &B, &C, &D, 0, 0)
	roundKeyUpdate1(roundKey, &A, &B, &C, &D, 1, 2)
	roundKeyUpdate0(roundKey, &A, &B, &C, &D, 2, 4)
	roundKeyUpdate1(roundKey, &A, &B, &C, &D, 3, 6)
	roundKeyUpdate0(roundKey, &A, &B, &C, &D, 4, 8)
	roundKeyUpdate1(roundKey, &A, &B, &C, &D, 5, 10)
	roundKeyUpdate0(roundKey, &A, &B, &C, &D, 6, 12)
	roundKeyUpdate1(roundKey, &A, &B, &C, &D, 7, 14)
	roundKeyUpdate0(roundKey, &A, &B, &C, &D, 8, 16)
	roundKeyUpdate1(roundKey, &A, &B, &C, &D, 9, 18)
	roundKeyUpdate0(roundKey, &A, &B, &C, &D, 10, 20)
	roundKeyUpdate1(roundKey, &A, &B, &C, &D, 11, 22)
	roundKeyUpdate0(roundKey, &A, &B, &C, &D, 12, 24)
	roundKeyUpdate1(roundKey, &A, &B, &C, &D, 13, 26)
	roundKeyUpdate0(roundKey, &A, &B, &C, &D, 14, 28)
	roundKeyUpdate1(roundKey, &A, &B, &C, &D, 15, 30)
}

func seedEncrypt(in []byte, out []byte, roundKey []uint32) {
	L0 := char2word(in, 0)
	L1 := char2word(in, 4)
	R0 := char2word(in, 8)
	R1 := char2word(in, 12)

	seedRound(&L0, &L1, &R0, &R1, roundKey, 0)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 2)
	seedRound(&L0, &L1, &R0, &R1, roundKey, 4)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 6)
	seedRound(&L0, &L1, &R0, &R1, roundKey, 8)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 10)
	seedRound(&L0, &L1, &R0, &R1, roundKey, 12)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 14)
	seedRound(&L0, &L1, &R0, &R1, roundKey, 16)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 18)
	seedRound(&L0, &L1, &R0, &R1, roundKey, 20)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 22)
	seedRound(&L0, &L1, &R0, &R1, roundKey, 24)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 26)
	seedRound(&L0, &L1, &R0, &R1, roundKey, 28)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 30)

	word2char(R0, out, 0)
	word2char(R1, out, 4)
	word2char(L0, out, 8)
	word2char(L1, out, 12)
}

func seedDecrypt(in []byte, out []byte, roundKey []uint32) {
	L0 := char2word(in, 0)
	L1 := char2word(in, 4)
	R0 := char2word(in, 8)
	R1 := char2word(in, 12)

	seedRound(&L0, &L1, &R0, &R1, roundKey, 30)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 28)
	seedRound(&L0, &L1, &R0, &R1, roundKey, 26)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 24)
	seedRound(&L0, &L1, &R0, &R1, roundKey, 22)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 20)
	seedRound(&L0, &L1, &R0, &R1, roundKey, 18)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 16)
	seedRound(&L0, &L1, &R0, &R1, roundKey, 14)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 12)
	seedRound(&L0, &L1, &R0, &R1, roundKey, 10)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 8)
	seedRound(&L0, &L1, &R0, &R1, roundKey, 6)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 4)
	seedRound(&L0, &L1, &R0, &R1, roundKey, 2)
	seedRound(&R0, &R1, &L0, &L1, roundKey, 0)

	word2char(R0, out, 0)
	word2char(R1, out, 4)
	word2char(L0, out, 8)
	word2char(L1, out, 12)
}
