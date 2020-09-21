package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"math/big"
)

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

//challenge factor pk_i*Hash(L,P_i)
func getChallengeFactor(Points [][]byte, pubKey []byte, pk *big.Int) *big.Int {
	var L []byte
	for _, point := range Points {
		L = append(L, point...)
	}

	var LPi []byte
	copy(LPi, L)
	LPi = append(LPi, pubKey...)
	hashed := sha256.Sum256(LPi)
	i := new(big.Int).SetBytes(hashed[:])
	i.Mul(i, pk)
	i.Mod(i, Curve.N)
	return i
}

//H(L,Pi)
func getChallengeFactorByIndex(Points [][]byte, index int) *big.Int {
	var L []byte
	for _, point := range Points {
		L = append(L, point...)
	}

	var LPi []byte
	copy(LPi, L)
	LPi = append(LPi, Points[index]...)
	hashed := sha256.Sum256(LPi)
	i := new(big.Int).SetBytes(hashed[:])
	//	i.Mul(i, pk)
	i.Mod(i, Curve.N)
	return i
}

func getAggregatePoints(points [][]byte) (aggPx, aggPy *big.Int, err error) {
	aggPx, aggPy = new(big.Int), new(big.Int)
	for _, point := range points {
		Px, Py, err := PointUnmarshal(point)
		if err != nil {
			return nil, nil, err
		}
		aggPx, aggPy = Curve.Add(aggPx, aggPy, Px, Py)
	}
	return aggPx, aggPy, nil
}

func generateMemberSignature(pkChallengeFactor, r, aggRx, aggRy, aggPx, aggPy *big.Int, message []byte) (s *big.Int) {
	r0 := r
	if big.Jacobi(aggRy, Curve.P) != 1 {
		aggRy.Sub(Curve.P, aggRy)
		r0.Sub(Curve.N, r0)
	}

	hashedNum := getHash(aggPx, aggPy, aggRx, message)
	hashedNum.Mul(hashedNum, pkChallengeFactor)

	r0.Add(r0, hashedNum)
	r0.Mod(r0, Curve.N)

	return r0
}

func aggreateMemberSignature(signs []*big.Int) (aggS *big.Int) {
	aggS = new(big.Int)

	for i := 0; i < len(signs); i++ {
		s := signs[i]
		aggS.Add(aggS, s)
	}
	aggS.Mod(aggS, Curve.N)
	return aggS
}

//func verify(aggRx, aggRy, aggPx, aggPy, s *big.Int, message []byte) {

//	hashedNum := getHash(aggPx, aggPy, aggRx, message)

//	verX, verY := Curve.ScalarMult()
//}

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

func TempMusig() {
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
}
