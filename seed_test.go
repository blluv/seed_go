package seedgo

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type cryptCase struct {
	key        []byte
	plainText  []byte
	cipherText []byte
}

var cases = []cryptCase{
	{
		[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		[]byte{0xC1, 0x1F, 0x22, 0xF2, 0x01, 0x40, 0x50, 0x50, 0x84, 0x48, 0x35, 0x97, 0xE4, 0x37, 0x0F, 0x43},
	},
	{
		[]byte{0x47, 0x06, 0x48, 0x08, 0x51, 0xE6, 0x1B, 0xE8, 0x5D, 0x74, 0xBF, 0xB3, 0xFD, 0x95, 0x61, 0x85},
		[]byte{0x83, 0xA2, 0xF8, 0xA2, 0x88, 0x64, 0x1F, 0xB9, 0xA4, 0xE9, 0xA5, 0xCC, 0x2F, 0x13, 0x1C, 0x7D},
		[]byte{0xEE, 0x54, 0xD1, 0x3E, 0xBC, 0xAE, 0x70, 0x6D, 0x22, 0x6B, 0xC3, 0x14, 0x2C, 0xD4, 0x0D, 0x4A},
	},
	{
		[]byte{0x28, 0xDB, 0xC3, 0xBC, 0x49, 0xFF, 0xD8, 0x7D, 0xCF, 0xA5, 0x09, 0xB1, 0x1D, 0x42, 0x2B, 0xE7},
		[]byte{0xB4, 0x1E, 0x6B, 0xE2, 0xEB, 0xA8, 0x4A, 0x14, 0x8E, 0x2E, 0xED, 0x84, 0x59, 0x3C, 0x5E, 0xC7},
		[]byte{0x9B, 0x9B, 0x7B, 0xFC, 0xD1, 0x81, 0x3C, 0xB9, 0x5D, 0x0B, 0x36, 0x18, 0xF4, 0x0F, 0x51, 0x22},
	},
}

func TestSeedEncrypt(t *testing.T) {
	for i, tcase := range cases {
		c, err := NewCipher(tcase.key)
		if err != nil {
			t.Errorf("NewCipher %d case: %s", i, err)
			return
		}
		dst := make([]byte, 16)
		c.Encrypt(dst, tcase.plainText)

		assert.Equal(t, dst, tcase.cipherText)
	}
}

func TestSeedDecrypt(t *testing.T) {
	for i, tcase := range cases {
		c, err := NewCipher(tcase.key)
		if err != nil {
			t.Errorf("NewCipher %d case: %s", i, err)
			return
		}
		dst := make([]byte, 16)
		c.Decrypt(dst, tcase.cipherText)

		assert.Equal(t, dst, tcase.plainText)
	}
}
