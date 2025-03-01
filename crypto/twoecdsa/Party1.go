package twoecdsa

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ffddz/upside-homework/crypto"
	"github.com/ffddz/upside-homework/crypto/mta"
	"github.com/ffddz/upside-homework/crypto/paillier"
	"math/big"
)

var (
	curve = secp256k1.S256()
)

// Party1 Alice
type Party1 struct {
	ek     *paillier.PublicKey
	x1     *big.Int
	beta   *big.Int
	k1     *big.Int
	r      *EcPoint
	Q1     *EcPoint
	Q2     *EcPoint
	PubKey *secp256k1.PublicKey // wallet public key
	alice  *mta.Alice
	alpha  *big.Int
}

// NewParty1 create new Party1
func NewParty1() *Party1 {
	x1 := crypto.RandomNum(curve.N)

	return &Party1{
		x1: x1,
	}
}

// KeyGenStep1 return aG
func (p *Party1) KeyGenStep1() (Q1 *EcPoint) {
	x, y := curve.ScalarBaseMult(p.x1.Bytes())

	q1 := &EcPoint{
		X: x,
		Y: y,
	}
	p.Q1 = q1
	return p.Q1
}

// KeyGenStep2 pubKey = Q1 + Q2
func (p *Party1) KeyGenStep2(Q2 *EcPoint) {
	pubKeyX, pubKeyY := curve.Add(p.Q1.X, p.Q1.Y, Q2.X, Q2.Y)
	xFieldVal := &secp256k1.FieldVal{}
	yFieldVal := &secp256k1.FieldVal{}
	xFieldVal.SetByteSlice(pubKeyX.Bytes())
	yFieldVal.SetByteSlice(pubKeyY.Bytes())
	p.PubKey = secp256k1.NewPublicKey(xFieldVal, yFieldVal)
	p.Q2 = Q2
}

func (p *Party1) SignStep1() (k1G *EcPoint) {
	p.k1 = crypto.RandomNum(curve.N)
	x, y := curve.ScalarBaseMult(p.k1.Bytes())
	return &EcPoint{
		X: x,
		Y: y,
	}
}

// SignStep2 r = k1k2G
func (p *Party1) SignStep2(k2G *EcPoint, prime, g, modulus *big.Int, rho int, otAList []*big.Int) []*big.Int {
	x, y := curve.ScalarMult(k2G.X, k2G.Y, p.k1.Bytes())
	p.r = &EcPoint{
		X: x,
		Y: y,
	}

	p.alice = mta.NewAlice(p.x1, prime, g, modulus, rho)
	otBList := p.alice.Step1(otAList)
	return otBList
}

func (p *Party1) SignStep3(c0List, c1List, nonceK0List, nonceK1List [][]byte) (z *EcPoint, err error) {
	alpha, err := p.alice.Step2(c0List, c1List, nonceK0List, nonceK1List)
	if err != nil {
		return nil, err
	}
	p.alpha = alpha
	x, y := curve.ScalarBaseMult(p.alpha.Bytes())
	z = &EcPoint{
		X: x,
		Y: y,
	}

	return z, nil
}

func (p *Party1) SignStep4(s2 *big.Int) (r *big.Int, s *big.Int, err error) {
	// s = k1_^{-1} * (s2 + alpha * r)
	k1Inv := new(big.Int).ModInverse(p.k1, curve.N)
	ar := new(big.Int).Mod(new(big.Int).Mul(p.alpha, p.r.X), curve.N)
	s = new(big.Int).Mod(new(big.Int).Add(s2, ar), curve.N)
	s = new(big.Int).Mod(new(big.Int).Mul(k1Inv, s), curve.N)

	return p.r.X, s, nil
}
