package tld_chain

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
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

func getChallengeFactorList(Points [][]byte) []*big.Int {
	var L []byte
	for _, point := range Points {
		L = append(L, point...)
	}

	var challengeFactorList []*big.Int
	for _, point := range Points {
		var hashPayload []byte
		copy(hashPayload, L[:])
		hashPayload = append(hashPayload, point...)
		hashedBytes := sha256.Sum256(hashPayload)
		challengeFactor := new(big.Int).SetBytes(hashedBytes[:])
		challengeFactor.Mod(challengeFactor, Curve.N)

		challengeFactorList = append(challengeFactorList, challengeFactor)
	}
	return challengeFactorList
}

func getHash(Px, Py, Rx *big.Int, message []byte) *big.Int {
	payload := append(Px.Bytes(), Py.Bytes()...)
	payload = append(payload, Rx.Bytes()...)
	payload = append(payload, message...)
	hashed := sha256.Sum256(payload)
	i := new(big.Int).SetBytes(hashed[:])
	return i.Mod(i, Curve.N)
}

func SimpleMusigTest() {
	var privateKeyList []*big.Int
	var privateRandomList []*big.Int

	for i := 0; i < 10; i++ {
		_, _, pk := GenerateKeyPair()
		_, _, r := GenerateKeyPair()

		privateKeyList = append(privateKeyList, pk)
		privateRandomList = append(privateRandomList, r)
	}

	//message := []byte("message")
	Rx, Ry := new(big.Int), new(big.Int)
	Px, Py := new(big.Int), new(big.Int)
	var publicKeyList [][]byte
	var publicRandomList [][]byte

	for i := 0; i < 10; i++ {
		privateKey := privateKeyList[i]
		privateRandom := privateRandomList[i]

		PiX, PiY := Curve.ScalarBaseMult(privateKey.Bytes())
		RiX, RiY := Curve.ScalarBaseMult(privateRandom.Bytes())

		Rx, Ry = Curve.Add(Rx, Ry, RiX, RiY)
		Px, Py = Curve.Add(Px, Py, PiX, PiY)

		bytePi := PointMarshal(PiX, PiY)
		byteRi := PointMarshal(RiX, RiY)

		publicKeyList = append(publicKeyList, bytePi)
		publicRandomList = append(publicRandomList, byteRi)
	}

	challengeFactorList := getChallengeFactorList(publicKeyList)

	var memberPrivateKeyList []*big.Int
	var memberPublicKeyList [][]byte

	for i := 0; i < 10; i++ {
		mpk := new(big.Int).Mul(privateKeyList[i], challengeFactorList[i])
		PiX, PiY, _ := PointUnmarshal(publicKeyList[i])
		mPiX, mPiY := Curve.ScalarMult(PiX, PiY, challengeFactorList[i].Bytes())

		memberPrivateKeyList = append(memberPrivateKeyList, mpk)
		memberPublicKeyList = append(memberPublicKeyList, PointMarshal(mPiX, mPiY))
	}

	aggMemPx, aggMemPy := new(big.Int).SetInt64(0), new(big.Int).SetInt64(0)
	aggPx, aggPy := new(big.Int).SetInt64(0), new(big.Int).SetInt64(0)
	aggRx, aggRy := new(big.Int).SetInt64(0), new(big.Int).SetInt64(0)
	for i := 0; i < 10; i++ {
		memPiX, memPiY, _ := PointUnmarshal(memberPublicKeyList[i])
		aggMemPx, aggMemPy = Curve.Add(aggMemPx, aggMemPy, memPiX, memPiY)
		RiX, RiY, err := PointUnmarshal(publicRandomList[i])
		if err != nil {
			fmt.Errorf(err.Error())
		}
		aggRx, aggRy = Curve.Add(aggRx, aggRy, RiX, RiY)
		PiX, PiY, _ := PointUnmarshal(publicKeyList[i])
		aggPx, aggPy = Curve.Add(aggPx, aggPy, PiX, PiY)
	}

	message := []byte("msg for signing")
	e := getHash(aggPx, aggPy, aggRx, message)
	s := new(big.Int).SetInt64(0)
	for i := 0; i < 10; i++ {
		si := new(big.Int).SetInt64(0)
		r0 := privateRandomList[i]
		r := new(big.Int).Set(r0)

		if big.Jacobi(aggRy, Curve.P) != 1 {
			r.Sub(Curve.N, r)
		}

		si.Set(e)
		si.Mul(si, memberPrivateKeyList[i])
		si.Add(si, r)

		s.Add(s, si)
	}

	//bug 1. 曾将aggRy的变形部分写进了循环，导致本来只需要变形一次，却变成了10次，很危险的bug，因为如果加密主体数量是奇数可能这个bug会被隐藏
//	if big.Jacobi(aggRy, Curve.P) != 1 {
//		aggRy.Sub(Curve.P, aggRy)
//	}

	/////////////////Verify////////////////////

	//	t.Log(hex.EncodeToString(s.Bytes()))

	sGx, sGy := Curve.ScalarBaseMult(s.Bytes())
	ePx, ePy := Curve.ScalarMult(aggMemPx, aggMemPy, e.Bytes())
	ePy.Sub(Curve.P, ePy)
	cRx, cRy := Curve.Add(sGx, sGy, ePx, ePy)

	//bug 2. 曾将验证过程写成和Curve.N的Jacobi
	fmt.Println(big.Jacobi(cRy, Curve.P))

	fmt.Println(hex.EncodeToString(sGx.Bytes()))
	fmt.Println(hex.EncodeToString(sGy.Bytes()))
	fmt.Println(hex.EncodeToString(ePx.Bytes()))
	fmt.Println(hex.EncodeToString(ePy.Bytes()))
	fmt.Println(hex.EncodeToString(aggRx.Bytes()))
	fmt.Println(hex.EncodeToString(cRx.Bytes()))
	fmt.Println(hex.EncodeToString(cRy.Bytes()))

	if (cRx.Sign() == 0 && cRy.Sign() == 0) || big.Jacobi(cRy, Curve.P) != 1 || cRx.Cmp(aggRx) != 0 {
		fmt.Println("verification failed")
	} else {
		fmt.Println("verification succeeded")
	}
}
