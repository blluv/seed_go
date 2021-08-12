package seedgo

import (
	"crypto/cipher"
	"strconv"
)

const BlockSize = 16
const RoundKeySize = 32

type seedCipher struct {
	roundKey []uint32
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "blluv/seedgo: invalid key size " + strconv.Itoa(int(k))
}

func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	if k != 16 {
		return nil, KeySizeError(k)
	}
	return newCipherGeneric(key)
}

func newCipherGeneric(key []byte) (cipher.Block, error) {
	c := seedCipher{make([]uint32, RoundKeySize)}
	seedRoundKey(key, c.roundKey)
	return &c, nil
}

func (c *seedCipher) BlockSize() int { return BlockSize }

func (c *seedCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("blluv/seedgo: input not full block")
	}
	if len(dst) < BlockSize {
		panic("blluv/seedgo: output not full block")
	}
	seedEncrypt(src, dst, c.roundKey)
}

func (c *seedCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("github.com/geeksbaek/seed128: input not full block")
	}
	if len(dst) < BlockSize {
		panic("github.com/geeksbaek/seed128: output not full block")
	}
	seedDecrypt(src, dst, c.roundKey)
}
