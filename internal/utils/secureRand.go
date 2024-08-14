package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"log"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

func randSecureNumber(bytesLen int) (uint64, error) {
	bRand := make([]byte, bytesLen)
	_, err := rand.Read(bRand)
	if err != nil {
		log.Printf("Could not read from rand source: %v", err)
		return 0, err
	}
	var randUInt64 uint64
	errBin := binary.Read(bytes.NewBuffer(bRand), binary.LittleEndian, &randUInt64)
	if errBin != nil {
		log.Printf("Could not convert byte-array (length: %d bytes) to uint64: %v", bytesLen, errBin)
		return 0, errBin
	}
	return randUInt64, nil
}

func RandString(n int) (string, error) {
	b := make([]byte, n)
	secureNum, err := randSecureNumber(8)
	if err != nil {
		return "", err
	}
	for i, cache, remain := n-1, secureNum, letterIdxMax; i >= 0; {
		if remain == 0 {
			secNum, err := randSecureNumber(8)
			if err != nil {
				return "", err
			}
			cache, remain = secNum, letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letters) {
			b[i] = letters[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b), nil
}
