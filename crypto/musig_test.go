package crypto

import (
	"encoding/hex"
	"testing"
)

func TestGenerateMemberSig(t *testing.T) {
	_, _, pk := GenerateKeyPair()
	_, _, r := GenerateKeyPair()

	message := []byte("fuckyou")

	sig, err := generateMemberSignature(pk, r, message)
	if err != nil {
		t.Error(err)
	}
	t.Log(hex.EncodeToString(sig[:]))
}

func TestHashRi(t *testing.T) {
	Rx, Ry, _ := GenerateKeyPair()
	hashedRi, err := getHashRi(Rx, Ry)

	if err != nil {
		t.Error(err)
	}
	t.Log(hashedRi)

	_, err = verifyHashRi(Rx,Ry,hashedRi)
	if err != nil {
		t.Error(err)
	}

}
