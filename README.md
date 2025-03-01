# 업사이드 아카데미 MPC 과제

## 제출 방법
아래 문제를 풀고 main 브랜치에 commit 후 push 하시오

평가는 각 테스트코드를 기반으로 이루어지며, 테스트코드 및 그외 다른 함수는 수정하지 마시오!

## 공개키 암호
### ElGamal 암호
crypto/elgamal/elgamal.go 의 Decrypt 을 구현하시오
```go
func (eg *ElGamal) Decrypt(c1, c2 *big.Int) (*big.Int, error) {

}
```

## 동형 암호
### 백만장자 문제

`crypto/millionaire/Party2.go` 의 `Step1`을 구현하시오

```go
func (p *Party2) Step1(c0 *big.Int) (c1 *big.Int, c2 *big.Int, err error) {

}
```

## Oblivious Transfer
### MtA

`crypto/mta/alice.go` 의 `Step2`를 구현하시오
```go
func (alice *Alice) Step2(c0List, c1List, nonceK0List, nonceK1List [][]byte) (*big.Int, error) {

}
```


## 디지털 서명

### 동일한 k로 서명한 경우 private key 추출 공격

`crypto/ecdsa/attack.go`의 `AttackGetPrivateKey`를 구현하시오

```go
func AttackGetPrivateKey(r1, s1, r2, s2 *big.Int, msg1, msg2 []byte) (*secp256k1.PrivateKey, error) {
	h1 := crypto.HashToInt(msg1)
	h2 := crypto.HashToInt(msg2)
	
	// TODO here	
}
```

## Lindell 17

### Passive Security 버전의 Lindell 17 구현

`crypto/lindell17/Party1.go` 의 `SignStep3`를 구현하시오

```go

// SignStep3 TODO Lindell17 Party1의 SignStep3를 구현하시오
func (p *Party1) SignStep3(h *big.Int) (c *big.Int, err error) {

}

```

## TwoECDSA
### Passive Security 버전의 2 ECDSA 구현

- `MtA` 문제를 먼저 풀어야 합니다.

`crypto/twoecdsa/Party2.go` 의 `SignStep4` 를 구현하시오

```go
func (p *Party2) SignStep4(z *EcPoint, h *big.Int) (s2 *big.Int, err error) {

}
```
