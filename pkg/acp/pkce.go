package acp

import (
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
	"strings"
	"time"
)

// ACP expects Challenge string to be at least 43 characters long
const challengeLength = 43

func GenerateChallenge(verifier string) string {
	hash := sha256.New()
	hash.Write([]byte(verifier))
	return encode(hash.Sum(nil))
}

func GenerateVerifier() string {
	verifier := make([]byte, challengeLength, challengeLength)
	rand := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < challengeLength; i++ {
		verifier[i] = byte(rand.Intn(255))
	}

	return encode(verifier)
}

func encode(msg []byte) string {
	encoded := base64.StdEncoding.EncodeToString(msg)
	encoded = strings.Replace(encoded, "+", "-", -1)
	encoded = strings.Replace(encoded, "/", "_", -1)
	encoded = strings.Replace(encoded, "=", "", -1)
	return encoded
}
