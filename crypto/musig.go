package crypto

import (
	"encoding/hex"
	"github.com/cloudflare/cfssl/scan/crypto/sha256"
	"github.com/pkg/errors"
	"math/big"
)

//todo this is wrong
func generateMemberSignature(pk, r *big.Int, message []byte) ([64]byte, error) {
	memberSignature, err := Sign(pk, r, message)
	if err != nil {
		return [64]byte{}, err
	}
	return memberSignature, nil
}

//Hash(R_i) in round one
func getHashRi(Rx, Ry *big.Int) (string, error) {
	bRx := Rx.Bytes()
	bRy := Ry.Bytes()
	if len(bRx) != 32 || len(bRy) != 32 {
		return "", errors.New("length of R not correct")
	}

	payload := append(bRx, bRy...)
	hashed := sha256.Sum256(payload)
	return string(hex.EncodeToString(hashed[:])), nil
}

func verifyHashRi(Rx, Ry *big.Int, hashedRi string) (bool, error) {
	verifyHash, err := getHashRi(Rx, Ry)
	if err != nil {
		return false, err
	}
	if verifyHash != hashedRi {
		return false, errors.New("hash not match")
	}
	return true, nil
}


