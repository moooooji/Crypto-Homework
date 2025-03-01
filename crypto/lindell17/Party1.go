package lindell17

import (
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ffddz/upside-homework/crypto"
	"github.com/ffddz/upside-homework/crypto/paillier"
	"math/big"
)

var (
	curve = secp256k1.S256()
)

// Party1 Alice
type Party1 struct {
	ek     *paillier.PublicKey
	a      *big.Int
	beta   *big.Int
	k1     *big.Int
	r      *EcPoint
	PubKey *secp256k1.PublicKey // wallet public key
}

// NewParty1 create new Party1
func NewParty1() *Party1 {
	a := crypto.RandomNum(curve.N)

	return &Party1{
		a: a,
	}
}

// KeyGenStep1 return aG
func (p *Party1) KeyGenStep1() (aG *EcPoint) {
	x, y := curve.ScalarBaseMult(p.a.Bytes())
	return &EcPoint{
		X: x,
		Y: y,
	}
}

// KeyGenStep2 pubKey = abG
func (p *Party1) KeyGenStep2(bG *EcPoint) {
	pubKeyX, pubKeyY := curve.ScalarMult(bG.X, bG.Y, p.a.Bytes())
	xFieldVal := &secp256k1.FieldVal{}
	yFieldVal := &secp256k1.FieldVal{}
	xFieldVal.SetByteSlice(pubKeyX.Bytes())
	yFieldVal.SetByteSlice(pubKeyY.Bytes())
	p.PubKey = secp256k1.NewPublicKey(xFieldVal, yFieldVal)
}

func (p *Party1) KeyGenStep3(ek *paillier.PublicKey, beta *big.Int) {
	p.ek = ek
	p.beta = beta
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
func (p *Party1) SignStep2(k2G *EcPoint) {
	x, y := curve.ScalarMult(k2G.X, k2G.Y, p.k1.Bytes())
	p.r = &EcPoint{
		X: x,
		Y: y,
	}
}

// SignStep3 TODO Lindell17 Party1의 SignStep3를 구현하시오
func (p *Party1) SignStep3(h *big.Int) (c *big.Int, err error) {
	return nil, fmt.Errorf("not implemented")
}
