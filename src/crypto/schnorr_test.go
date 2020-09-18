package crypto

import (
	"math/big"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	PubX, PubY, _ := GenerateKeyPair()
	//	t.Log(priv)
	bytesOfPoint := PointMarshal(PubX, PubY)
	PubXunmarshal, PubYunmarshal, err := PointUnmarshal(bytesOfPoint)

	if err != nil {
		t.Error(err)
	}

	if PubX.Cmp(PubXunmarshal) != 0 || PubY.Cmp(PubYunmarshal) != 0 {
		t.Error("point become different after marshal and unmarshal")
	}
}

func TestSignature(t *testing.T) {
	Px, Py, pk := GenerateKeyPair()
	Rx, _, r := GenerateKeyPair()

	msg := []byte("fuckyoufuckyoufuccccc")
	signature, _ := Sign(pk, r, msg)

	s := new(big.Int).SetBytes(signature[32:])
	_, err := Verify(Px, Py, Rx, s, msg)
	if err != nil {
		t.Error(err)
	}
}

func TestVerify(t *testing.T) {
	Px, Py, pk := GenerateKeyPair()
	_, _, r := GenerateKeyPair()

	msg := []byte("jy i love")
	signature, err := Sign(pk, r, msg)
	if err != nil {
		t.Error(err)
	}
	ok, err := VerifyMsg(signature, msg, Px, Py)
	if !ok || err != nil {
		t.Error(err)
	}

}

func TestVerifyFault(t *testing.T) {
	Px, Py, pk := GenerateKeyPair()
	_, _, r := GenerateKeyPair()

	msg := []byte("jy i love")
	signature, err := Sign(pk, r, msg)
	if err != nil {
		t.Error(err)
	}

	signature[50] = byte(22)
	ok, err := VerifyMsg(signature, msg, Px, Py)

	if ok {
		t.Error("It should not be ok ! There is about 1/256 to get ok")
	}
}
