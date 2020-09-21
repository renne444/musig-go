package crypto

// 模仿自https://github.com/hbakhtiyor/schnorr/blob/master/schnorr.go
import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/cloudflare/cfssl/scan/crypto/sha256"
	"math/big"
)

var (
	Curve = btcec.S256()
)

func GenerateKeyPair() (Px, Py, pk *big.Int) {
	key, err := ecdsa.GenerateKey(Curve, rand.Reader)
	if err != nil {
		fmt.Println(err)
	}

	return key.X, key.Y, key.D
}

func PointMarshal(Px, Py *big.Int) (ret []byte) {
	ret = []byte{}
	bPx, bPy := [32]byte{}, [32]byte{}
	copy(bPx[32-len(Px.Bytes()):], Px.Bytes())
	copy(bPy[32-len(Py.Bytes()):], Py.Bytes())

	ret = append(ret, bPx[:]...)
	ret = append(ret, bPy[:]...)

	return ret

}

func getJacobiResult(Ry, r *big.Int) *big.Int {
	if big.Jacobi(Ry, Curve.P) == 1 {
		return r
	}
	return r.Sub(Curve.N, r)
}

func PointUnmarshal(src []byte) (Px, Py *big.Int, err error) {
	bPx := src[:32]
	bPy := src[32:]

	if len(bPx) != 32 || len(bPy) != 32 {
		return nil, nil,
			errors.New(fmt.Sprintf("Point Unmarshal Error because of length, with bPx = %d, bPy = %d",
				len(bPx), len(bPy)))

	}

	Px = big.NewInt(0).SetBytes(bPx)
	Py = big.NewInt(0).SetBytes(bPy)

	return Px, Py, nil
}

//H(P, Rx, m)
func getHash(Px, Py, Rx *big.Int, message []byte) *big.Int {
	payload := append(Px.Bytes(), Py.Bytes()...)
	payload = append(payload, Rx.Bytes()...)
	payload = append(payload, message...)
	hashed := sha256.Sum256(payload)
	i := new(big.Int).SetBytes(hashed[:])
	return i.Mod(i, Curve.N)
}

// s = r+H(P, Rx, m)* pk
func Sign(pk, r *big.Int, message []byte) ([64]byte, error) {

	Rx, Ry := Curve.ScalarBaseMult(r.Bytes())
	r0 := getJacobiResult(Ry, r)
	Px, Py := Curve.ScalarBaseMult(pk.Bytes())
	hashedNum := getHash(Px, Py, Rx, message)

	hashedNum.Mul(hashedNum, pk)
	r0.Add(r0, hashedNum)
	r0.Mod(r0, Curve.N)

	sig := [64]byte{}
	copy(sig[:32], Rx.Bytes())
	copy(sig[32:], r0.Bytes())
	return sig, nil
}

//s*G = r*G + H*pk*G
func Verify(Px, Py, Rx, s *big.Int, message []byte) (bool, error) {

	if !Curve.IsOnCurve(Px, Py) {
		return false, errors.New("signature verification failed, Public Key error")
	}
	hashedNum := getHash(Px, Py, Rx, message)

	sGx, sGy := Curve.ScalarBaseMult(s.Bytes())
	fmt.Println(fmt.Sprintf("[verify] sGx = %s", hex.EncodeToString(sGx.Bytes())))
	fmt.Println(fmt.Sprintf("[verify] sGx = %s", hex.EncodeToString(sGy.Bytes())))

	ePx, ePy := Curve.ScalarMult(Px, Py, hashedNum.Bytes())
	ePy.Sub(Curve.P, ePy)
	fmt.Println(fmt.Sprintf("[verify] ePx = %s", hex.EncodeToString(ePx.Bytes())))
	fmt.Println(fmt.Sprintf("[verify] ePy = %s", hex.EncodeToString(ePy.Bytes())))

	RxCalc, RyCalc := Curve.Add(sGx, sGy, ePx, ePy)
	fmt.Println(fmt.Sprintf("[verify] rx = %s", hex.EncodeToString(RxCalc.Bytes())))
	fmt.Println(fmt.Sprintf("[verify] ry = %s", hex.EncodeToString(RyCalc.Bytes())))

	if RxCalc.Sign() == 0 && RyCalc.Sign() == 0 {
		return false, errors.New("signature verification failed, get zero Rx and Ry")
	} else if big.Jacobi(RyCalc, Curve.P) != 1 {
		return false, errors.New("signature verification failed, Jacobi verification fail")
	} else if RxCalc.Cmp(Rx) != 0 {
		return false, errors.New("signature verification failed, Rx verification fail")
	}

	return true, nil
}

func VerifyMsg(signature [64]byte, message []byte, Px, Py *big.Int) (bool, error) {
	s := new(big.Int).SetBytes(signature[32:])
	Rx := new(big.Int).SetBytes(signature[:32])
	return Verify(Px, Py, Rx, s, message)
}
