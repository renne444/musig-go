package crypto

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func TestHashRi(t *testing.T) {
	Rx, Ry, _ := GenerateKeyPair()
	hashedRi, err := getHashRi(Rx, Ry)

	if err != nil {
		t.Error(err)
	}
	t.Log(hashedRi)

	_, err = verifyHashRi(Rx, Ry, hashedRi)
	if err != nil {
		t.Error(err)
	}

}

func TestGetChallengeFactor(t *testing.T) {

	var publicKeyList [][]byte
	var privateKeyList []*big.Int

	for i := 0; i < 10; i++ {
		Px, Py, pk := GenerateKeyPair()
		publicKeyList = append(publicKeyList, PointMarshal(Px, Py))
		privateKeyList = append(privateKeyList, pk)
	}
	factor := getChallengeFactor(publicKeyList, publicKeyList[0], privateKeyList[0])
	t.Log(hex.EncodeToString(factor.Bytes()))
}

func TestPointAggregation(t *testing.T) {
	var publicKeyList [][]byte
	var privateKeyList []*big.Int

	for i := 0; i < 10; i++ {
		Px, Py, pk := GenerateKeyPair()
		publicKeyList = append(publicKeyList, PointMarshal(Px, Py))
		privateKeyList = append(privateKeyList, pk)
	}
	aggX, aggY, err := getAggregatePoints(publicKeyList)
	if err != nil {
		t.Error(err)
	}
	t.Log(fmt.Sprintf("key aggreation, with X = %s, Y = %s", hex.EncodeToString(aggX.Bytes()), hex.EncodeToString(aggY.Bytes())))
}

func TestGetMembershipSignature(t *testing.T) {

	var publicKeyList [][]byte
	var privateKeyList []*big.Int

	var RList [][]byte
	var rList []*big.Int
	for i := 0; i < 10; i++ {
		Px, Py, pk := GenerateKeyPair()
		Rx, Ry, r := GenerateKeyPair()
		publicKeyList = append(publicKeyList, PointMarshal(Px, Py))
		privateKeyList = append(privateKeyList, pk)
		RList = append(RList, PointMarshal(Rx, Ry))
		rList = append(rList, r)
	}
	aggPx, aggPy, err := getAggregatePoints(publicKeyList)
	aggRx, aggRy, err := getAggregatePoints(RList)

	if err != nil {
		t.Error(err)
	}

	message := []byte("fuickyou")
	generateMemberSignature(getChallengeFactor(publicKeyList, publicKeyList[0], privateKeyList[0]), rList[0], aggRx, aggRy, aggPx, aggPy, message)

}

func TestMainTest(t *testing.T) {
	var publicKeyList [][]byte
	var privateKeyList []*big.Int

	var RList [][]byte
	var rList []*big.Int
	for i := 0; i < 10; i++ {
		Px, Py, pk := GenerateKeyPair()
		Rx, Ry, r := GenerateKeyPair()
		publicKeyList = append(publicKeyList, PointMarshal(Px, Py))
		privateKeyList = append(privateKeyList, pk)
		RList = append(RList, PointMarshal(Rx, Ry))
		rList = append(rList, r)
	}
	aggPx, aggPy, err := getAggregatePoints(publicKeyList)
	aggRx, aggRy, err := getAggregatePoints(RList)

	if err != nil {
		t.Error(err)
	}

	message := []byte("fuickyou")

	var aggSlist []*big.Int

	for i := 0; i < 10; i++ {
		aggSTemp := generateMemberSignature(getChallengeFactor(publicKeyList, publicKeyList[0], privateKeyList[0]), rList[0], aggRx, aggRy, aggPx, aggPy, message)
		aggSlist = append(aggSlist, aggSTemp)
	}
	aggSCalc := aggreateMemberSignature(aggSlist)
	t.Log(hex.EncodeToString(aggSCalc.Bytes()))

	////verify test

	verX, verY := new(big.Int), new(big.Int)

	verHashedNum := getHash(aggPx, aggPy, aggRx, message)
	//	publicKeyChallengeFactor := getChallengeFactorWithPubKey(publicKeyList)
	for i := 0; i < 10; i++ {
		Pix, Piy, _ := PointUnmarshal(publicKeyList[i])
		publicKeyFactor := getChallengeFactorByIndex(publicKeyList, i)
		tempX, tempY := Curve.ScalarMult(Pix, Piy, publicKeyFactor.Bytes())
		tempX, tempY = Curve.ScalarMult(tempX, tempY, verHashedNum.Bytes())

		verX, verY = Curve.Add(verX, verY, tempX, tempY)
	}

	verX, verY = Curve.Add(verX, verY, aggRx, aggRy)

	verX2, verY2 := Curve.ScalarBaseMult(aggSCalc.Bytes())

	t.Log(hex.EncodeToString(PointMarshal(verX, verY)))
	t.Log(hex.EncodeToString(PointMarshal(verX2, verY2)))

}

//func TestMainTest2(t *testing.T) {
//	var publicKeyList [][]byte
//	var privateKeyList []*big.Int
//
//	var RList [][]byte
//	var rList []*big.Int
//
//	for i := 0; i < 10; i++ {
//		Px, Py, pk := GenerateKeyPair()
//		Rx, Ry, r := GenerateKeyPair()
//		publicKeyList = append(publicKeyList, PointMarshal(Px, Py))
//		privateKeyList = append(privateKeyList, pk)
//		RList = append(RList, PointMarshal(Rx, Ry))
//		rList = append(rList, r)
//	}
//
//
//}

func TestSimpleSchnorrSignatureAggression(t *testing.T) {

	var privateKeyList []*big.Int
	var privateRandomList []*big.Int
	for i := 0; i < 10; i++ {
		_, _, pk := GenerateKeyPair()
		_, _, r := GenerateKeyPair()

		privateKeyList = append(privateKeyList, pk)
		privateRandomList = append(privateRandomList, r)
	}

	message := []byte("message")

	Rx, Ry := new(big.Int), new(big.Int)
	Px, Py := new(big.Int), new(big.Int)
	for i := 0; i < 10; i++ {
		privateKey := privateKeyList[i]
		privateRandom := privateRandomList[i]

		PiX, PiY := Curve.ScalarBaseMult(privateKey.Bytes())
		RiX, RiY := Curve.ScalarBaseMult(privateRandom.Bytes())

		Rx, Ry = Curve.Add(Rx, Ry, RiX, RiY)
		Px, Py = Curve.Add(Px, Py, PiX, PiY)
	}

	e := getHash(Px, Py, Rx, message)
	s := new(big.Int).SetInt64(0)

	for i, r0 := range privateRandomList {
		r := getJacobiResult(Ry, r0)
		//	r := r0
		r.Add(r, new(big.Int).Mul(e, privateKeyList[i]))
		s.Add(s, r)
	}

	// Rx and s is the final signature
	t.Log(hex.EncodeToString(Rx.Bytes()))
	t.Log(hex.EncodeToString(s.Bytes()))

	t.Log(Verify(Px, Py, Rx, s, message))
}

func TestExp(t *testing.T) {
	Rx, Ry, pk := GenerateKeyPair()
	//pk0 := getJacobiResult(Ry, pk)

	t.Log("Rx:" + hex.EncodeToString(Rx.Bytes()))
	t.Log("Ry:" + hex.EncodeToString(Ry.Bytes()))

	if big.Jacobi(Ry, Curve.P) != 1 {

		pk0 := new(big.Int).Set(pk)
		pk0 = getJacobiResult(Ry, pk0)
		t.Log("pk:" + hex.EncodeToString(pk.Bytes()))
		R1x, R1y := Curve.ScalarBaseMult(pk.Bytes())
		t.Log("R1x:" + hex.EncodeToString(R1x.Bytes()))
		t.Log("R1y:" + hex.EncodeToString(R1y.Bytes()))

		t.Log("pk0:" + hex.EncodeToString(pk0.Bytes()))
		R2x, R2y := Curve.ScalarBaseMult(pk0.Bytes())
		t.Log("R2x:" + hex.EncodeToString(R2x.Bytes()))
		t.Log("R2y:" + hex.EncodeToString(R2y.Bytes()))

		test := new(big.Int).Set(R1y)
		test.Sub(Curve.P, test)
		t.Log("test:" + hex.EncodeToString(test.Bytes()))
	} else {
		t.Error("fuckyou")
	}

}

func TestMuSig(t *testing.T) {
	TempMusig()
}
