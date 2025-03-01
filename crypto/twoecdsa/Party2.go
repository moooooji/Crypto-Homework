package twoecdsa

import (
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ffddz/upside-homework/crypto"
	"github.com/ffddz/upside-homework/crypto/mta"
	"math/big"
)

// Bob
type Party2 struct {
	x2     *big.Int
	k2     *big.Int
	r      *EcPoint
	Q1     *EcPoint
	Q2     *EcPoint
	PubKey *secp256k1.PublicKey
	bob    *mta.Bob
	beta   *big.Int
}

// Bob
func NewParty2() *Party2 {
	b := crypto.RandomNum(curve.N)

	return &Party2{
		x2: b,
	}
}

func (p *Party2) KeyGenStep1() (Q2 *EcPoint) {
	x, y := curve.ScalarBaseMult(p.x2.Bytes())
	q2 := &EcPoint{
		X: x,
		Y: y,
	}

	p.Q2 = q2
	return p.Q2
}

func (p *Party2) KeyGenStep2(Q1 *EcPoint) {
	pubKeyX, pubKeyY := curve.Add(Q1.X, Q1.Y, p.Q2.X, p.Q2.Y)
	xFieldVal := &secp256k1.FieldVal{}
	yFieldVal := &secp256k1.FieldVal{}
	xFieldVal.SetByteSlice(pubKeyX.Bytes())
	yFieldVal.SetByteSlice(pubKeyY.Bytes())
	p.PubKey = secp256k1.NewPublicKey(xFieldVal, yFieldVal)
	p.Q1 = Q1
}

func (p *Party2) SignStep1() (k1G *EcPoint) {
	p.k2 = crypto.RandomNum(curve.N)
	x, y := curve.ScalarBaseMult(p.k2.Bytes())
	return &EcPoint{
		X: x,
		Y: y,
	}
}

// SignStep2 r = k1k2G
func (p *Party2) SignStep2(k1G *EcPoint, prime, g, modulus *big.Int, rho int) ([]*big.Int, error) {
	x, y := curve.ScalarMult(k1G.X, k1G.Y, p.k2.Bytes())
	p.r = &EcPoint{
		X: x,
		Y: y,
	}
	k2Inv := new(big.Int).ModInverse(p.k2, curve.N)
	p.bob = mta.NewBob(k2Inv, prime, g, modulus, rho)
	otAList := p.bob.Step1()
	return otAList, nil
}

func (p *Party2) SignStep3(otBList []*big.Int) ([][]byte, [][]byte, [][]byte, [][]byte, error) {
	c0List, c1List, nonceK0List, nonceK1List, beta, err := p.bob.Step2(otBList)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	p.beta = beta
	return c0List, c1List, nonceK0List, nonceK1List, nil
}

// TODO SignStep4 k2(z+betaP) == Q1 검증 및 s2 = k_2^{-1}(h + r * x_2) + b*r 계산
func (p *Party2) SignStep4(z *EcPoint, h *big.Int) (s2 *big.Int, err error) {
	return nil, fmt.Errorf("not implemented")
}
