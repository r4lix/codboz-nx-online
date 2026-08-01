package bitdemon

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
)

const (
	tigerBlockSize  = 64
	tigerDigestSize = 24
)

var tigerSBoxes = loadTigerSBoxes()

func Tiger192(payload []byte) [tigerDigestSize]byte {
	a := uint64(0x0123456789abcdef)
	b := uint64(0xfedcba9876543210)
	c := uint64(0xf096a5b4c3b2e187)

	padded := tigerPad(payload)
	for offset := 0; offset < len(padded); offset += tigerBlockSize {
		var words [8]uint64
		for index := range words {
			start := offset + index*8
			words[index] = binary.LittleEndian.Uint64(padded[start : start+8])
		}
		tigerCompress(&a, &b, &c, &words)
	}

	var digest [tigerDigestSize]byte
	binary.LittleEndian.PutUint64(digest[0:8], a)
	binary.LittleEndian.PutUint64(digest[8:16], b)
	binary.LittleEndian.PutUint64(digest[16:24], c)
	return digest
}

func tigerPad(payload []byte) []byte {
	lengthWithMarker := len(payload) + 1
	zeroCount := (56 - lengthWithMarker%tigerBlockSize + tigerBlockSize) % tigerBlockSize
	padded := make([]byte, lengthWithMarker+zeroCount+8)
	copy(padded, payload)
	padded[len(payload)] = 0x01
	binary.LittleEndian.PutUint64(padded[len(padded)-8:], uint64(len(payload))*8)
	return padded
}

func tigerCompress(a, b, c *uint64, words *[8]uint64) {
	originalA, originalB, originalC := *a, *b, *c

	tigerPass(a, b, c, words, 5)
	tigerKeySchedule(words)
	tigerPass(c, a, b, words, 7)
	tigerKeySchedule(words)
	tigerPass(b, c, a, words, 9)

	*a ^= originalA
	*b -= originalB
	*c += originalC
}

func tigerPass(a, b, c *uint64, words *[8]uint64, multiplier uint64) {
	tigerRound(a, b, c, words[0], multiplier)
	tigerRound(b, c, a, words[1], multiplier)
	tigerRound(c, a, b, words[2], multiplier)
	tigerRound(a, b, c, words[3], multiplier)
	tigerRound(b, c, a, words[4], multiplier)
	tigerRound(c, a, b, words[5], multiplier)
	tigerRound(a, b, c, words[6], multiplier)
	tigerRound(b, c, a, words[7], multiplier)
}

func tigerRound(a, b, c *uint64, word, multiplier uint64) {
	*c ^= word
	value := *c
	*a -= tigerSBoxes[0][byte(value)] ^
		tigerSBoxes[1][byte(value>>16)] ^
		tigerSBoxes[2][byte(value>>32)] ^
		tigerSBoxes[3][byte(value>>48)]
	*b += tigerSBoxes[3][byte(value>>8)] ^
		tigerSBoxes[2][byte(value>>24)] ^
		tigerSBoxes[1][byte(value>>40)] ^
		tigerSBoxes[0][byte(value>>56)]
	*b *= multiplier
}

func tigerKeySchedule(words *[8]uint64) {
	words[0] -= words[7] ^ 0xa5a5a5a5a5a5a5a5
	words[1] ^= words[0]
	words[2] += words[1]
	words[3] -= words[2] ^ (^words[1] << 19)
	words[4] ^= words[3]
	words[5] += words[4]
	words[6] -= words[5] ^ (^words[4] >> 23)
	words[7] ^= words[6]
	words[0] += words[7]
	words[1] -= words[0] ^ (^words[7] << 19)
	words[2] ^= words[1]
	words[3] += words[2]
	words[4] -= words[3] ^ (^words[2] >> 23)
	words[5] ^= words[4]
	words[6] += words[5]
	words[7] -= words[6] ^ 0x0123456789abcdef
}

func loadTigerSBoxes() [4][256]uint64 {
	encoded := strings.ReplaceAll(tigerSBoxesBase64, "\n", "")
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic("decode Tiger S-boxes: " + err.Error())
	}
	if len(data) != 4*256*8 {
		panic("decode Tiger S-boxes: unexpected table length")
	}

	var tables [4][256]uint64
	for tableIndex := range tables {
		for entryIndex := range tables[tableIndex] {
			offset := (tableIndex*256 + entryIndex) * 8
			tables[tableIndex][entryIndex] = binary.LittleEndian.Uint64(data[offset : offset+8])
		}
	}
	return tables
}
