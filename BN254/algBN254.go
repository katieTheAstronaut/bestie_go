package main

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/miracl/core/go/core"
	"github.com/miracl/core/go/core/BN254"
)

// ----------- Structs

type pk struct {
	p          *BN254.BIG
	g1         *BN254.ECP
	g2         *BN254.ECP2
	h0         *BN254.ECP
	k0         *BN254.ECP
	helements0 []*BN254.ECP
	helements1 []*BN254.ECP
	kelements0 []*BN254.ECP
	kelements1 []*BN254.ECP
	omega      *BN254.FP12
}

type sk struct {
	x0        *BN254.ECP
	xelements []*BN254.ECP
	y0        *BN254.ECP
	yEven     []*BN254.ECP
	yOdd      []*BN254.ECP
	z         *BN254.ECP2
}

type hdr struct {
	c0 *BN254.FP12
	c1 *BN254.ECP2
	c2 *BN254.ECP
	c3 *BN254.ECP
}

type subset struct {
	cl string
	rl string
}

// ----------- Package Scope Variables
var rng *core.RAND

// Setup Algorithm (l,lambda) -> PK,MK
func setup(l int) (pubKey *pk, mk *BN254.ECP) {
	// ----------- Setup 1
	// Generate bilinear groups of order p (already done once you chose the curve)
	p := BN254.NewBIGints(BN254.Modulus)
	q := BN254.NewBIGints(BN254.CURVE_Order)

	// ----------- Setup 2
	// Select two random elements g1 in G1 and g2 in G2
	// these have to be generators, so multiplying with these points creates new valid points on the curve
	g1 := BN254.ECP_generator()
	g2 := BN254.ECP2_generator()

	// ----------- Setup 3
	// Select random exponent alpha in Zp
	// q needs to be modulus to ensure valid new ECP
	alpha := BN254.Randomnum(q, rng)

	// ----------- Setup 4
	// Select random group elements
	// h1,0 ... hl,0 and h1,1 ... hl,1 in two slices for readability
	h0Rand := BN254.Randomnum(q, rng)
	h0 := BN254.G1mul(g1, h0Rand)

	hrands0 := make([]*BN254.BIG, l)    // slice for random numbers h1,0 ... hl,0
	helements0 := make([]*BN254.ECP, l) // Slice for resulting random group elements of G1
	for i := 0; i < l; i++ {
		hrands0[i] = BN254.Randomnum(q, rng)
		helements0[i] = BN254.G1mul(g1, hrands0[i])
	}

	hrands1 := make([]*BN254.BIG, l)    // slice for random numbers h1,1 ... hl,1
	helements1 := make([]*BN254.ECP, l) // Slice for resulting random group elements of G1
	for i := 0; i < l; i++ {
		hrands1[i] = BN254.Randomnum(q, rng)
		helements1[i] = BN254.G1mul(g1, hrands1[i])
	}

	// k0, k1,0 ... kl,1
	k0Rand := BN254.Randomnum(q, rng)
	k0 := BN254.G1mul(g1, k0Rand)

	krands0 := make([]*BN254.BIG, l)    // slice for random numbers k1,0 ... kl,0
	kelements0 := make([]*BN254.ECP, l) // Slice for resulting random group elements of G1
	for i := 0; i < l; i++ {
		krands0[i] = BN254.Randomnum(q, rng)
		kelements0[i] = BN254.G1mul(g1, krands0[i])
	}

	krands1 := make([]*BN254.BIG, l)    // slice for random numbers k1,1 ... kl,1
	kelements1 := make([]*BN254.ECP, l) // Slice for resulting random group elements of G1
	for i := 0; i < l; i++ {
		krands1[i] = BN254.Randomnum(q, rng)
		kelements1[i] = BN254.G1mul(g1, krands1[i])
	}

	// ----------- Setup 5
	// Return master key MK = g1^alpha
	mk = BN254.G1mul(g1, alpha)

	// ----------- Setup 6
	// compute pairing Omega = e(g1,g2)^alpha
	omega := BN254.Ate(g2, g1)
	omega = BN254.Fexp(omega)
	omega = omega.Pow(alpha)
	// Return Public Key / Public Parameters
	pubKey = &pk{p, g1, g2, h0, k0, helements0, helements1, kelements0, kelements1, omega}

	return pubKey, mk
}

// KeyGen Algorithm (user's ID, MK, PK) -> SK_ID
func keyGen(id string, mk *BN254.ECP, pubKey *pk) (secKey *sk) {

	q := BN254.NewBIGints(BN254.CURVE_Order)
	l := len(id)
	// ----------- KeyGen 1
	// 1. Select two random exponents alpha_omega and r in Zp
	alphaOmega := BN254.Randomnum(q, rng)
	r := BN254.Randomnum(q, rng)

	// ----------- KeyGen 2
	// Create private key SK_ID

	// ---x0
	//// g1^(alpha-alphaOmega) = mk / mk2 where mk2 = g1^alphaOmega
	mk1 := BN254.NewECP()
	mk1.Copy(mk)
	mk2 := BN254.G1mul(pubKey.g1, alphaOmega)
	g1AlphaOmega := BN254.NewECP()
	g1AlphaOmega.Copy(mk2) // We need a an unchanged version of mk2 for later
	mk2.Neg()              // compute mk2^-1
	mk1.Add(mk2)           // mk * mk2^-1

	hID := BN254.NewECP()
	hID.Copy(pubKey.h0) // deep copy of ECP via ECP.Copy() method
	for i := 0; i < l; i++ {
		if string(id[i]) == "0" {
			hID.Add(pubKey.helements0[i])
		} else if string(id[i]) == "1" {
			hID.Add(pubKey.helements1[i])
		} else {
			fmt.Println("ID could not be read")
		}
	}
	hExp := BN254.G1mul(hID, r)
	hExp.Add(mk1)
	x0 := hExp

	// ---x1 - xl
	xelements := make([]*BN254.ECP, l)
	for i := 0; i < l; i++ {
		if string(id[i]) == "0" {
			xelements[i] = BN254.G1mul(pubKey.helements1[i], r)
		} else if string(id[i]) == "1" {
			xelements[i] = BN254.G1mul(pubKey.helements0[i], r)
		} else {
			fmt.Println("ID could not be read")
		}
	}

	// -- y0
	y0 := BN254.G1mul(pubKey.k0, r)

	// -- y1...y2l
	//// two slices of odd and even for readability
	yOdd := make([]*BN254.ECP, l)
	yEven := make([]*BN254.ECP, l)
	for i := 0; i < l; i++ {
		if string(id[i]) == "0" {
			temp := BN254.G1mul(pubKey.kelements1[i], r)
			temp.Add(g1AlphaOmega)
			yOdd[i] = temp
			yEven[i] = BN254.G1mul(pubKey.kelements0[i], r)
		} else if string(id[i]) == "1" {
			temp := BN254.G1mul(pubKey.kelements0[i], r)
			temp.Add(g1AlphaOmega)
			yOdd[i] = temp
			yEven[i] = BN254.G1mul(pubKey.kelements1[i], r)
		} else {
			fmt.Println("ID could not be read")
		}
	}

	// z
	z := BN254.G2mul(pubKey.g2, r)

	// return private key
	secKey = &sk{x0, xelements, y0, yEven, yOdd, z}
	return secKey
}

// Encrypt(S=(CL,RL), PK, and message M) -> Header HdrS)
func encrypt(s *subset, pubKey *pk, message *BN254.FP12) (cipher *hdr) {

	q := BN254.NewBIGints(BN254.CURVE_Order)
	l := len(s.cl)

	// ----------- Encrypt 1
	// Select random exponent t in Zp
	t := BN254.Randomnum(q, rng)

	// ----------- Encrypt 2
	// Return ciphertext Hdr = (C0, C1, C2 C3)

	// C0 = omega^t * M (both GT elements)
	c0 := pubKey.omega.Pow(t)
	c0.Mul(message)

	// c1 = g2^t
	c1 := BN254.G2mul(pubKey.g2, t)

	// c2 = H(CL)^t
	hcl := BN254.NewECP()
	hcl.Copy(pubKey.h0)
	for i := 0; i < l; i++ {
		if string(s.cl[i]) == "0" {
			hcl.Add(pubKey.helements0[i])
		} else if string(s.cl[i]) == "1" {
			hcl.Add(pubKey.helements1[i])
		} else if string(s.cl[i]) == "*" {
			hProd := BN254.NewECP()
			hProd.Copy(pubKey.helements0[i])
			hProd.Add(pubKey.helements1[i])
			hcl.Add(hProd)
		} else {
			fmt.Println("CL could not be read")
		}
	}
	c2 := BN254.G1mul(hcl, t)

	// c3 = K(RL)^t
	krl := BN254.NewECP()
	krl.Copy(pubKey.k0)
	for i := 0; i < l; i++ {
		if string(s.rl[i]) == "0" {
			krl.Add(pubKey.kelements0[i])
		} else if string(s.rl[i]) == "1" {
			krl.Add(pubKey.kelements1[i])
		} else if string(s.rl[i]) == "*" {
			// * - Do nothing
		} else {
			fmt.Println("RL could not be read")
		}
	}
	c3 := BN254.G1mul(krl, t)

	cipher = &hdr{c0, c1, c2, c3}
	return cipher
}

// Decrypt(S=(CL,RL),ID,SK_ID,HdrS) -> M or error
func decrypt(s *subset, id string, secKey *sk, cipher *hdr) (mes *BN254.FP12, err error) {

	l := len(id)

	// ----------- Decrypt 1
	// compute P = bits that are different from revoked list
	// i.e. set of indexes of ID, where ID not equal to revoked set and revoked set not *
	pRl := []int{}
	for i := 0; i < l; i++ {
		if string(s.rl[i]) != "*" && id[i] != s.rl[i] {
			pRl = append(pRl, i+1)
		}
	}

	// ----------- Decrypt 2
	// compute Q = bits that are equal to revoked set
	qRl := []int{}
	for i := 0; i < l; i++ {
		if string(s.rl[i]) != "*" && id[i] == s.rl[i] {
			qRl = append(qRl, i+1)
		}
	}

	// ----------- Decrypt 3
	// compute d = |P|
	d := len(pRl)

	// ----------- Decrypt 4
	// if d > 0, decrypt message, else return error

	if d > 0 {
		// compute x'
		xAp := BN254.NewECP()
		xAp.Copy(secKey.x0)
		for i := 0; i < l; i++ {
			if string(s.cl[i]) == "*" {
				xAp.Add(secKey.xelements[i])
			}
		}

		// compute y'
		yAp := BN254.NewECP()
		yAp.Copy(secKey.y0)
		for i := 1; i < l+1; i++ {
			if contains(pRl, i) {
				yAp.Add(secKey.yOdd[i-1])
			}
		}
		for i := 1; i < l+1; i++ {
			if contains(qRl, i) {
				yAp.Add(secKey.yEven[i-1])
			}
		}
		dExp := BN254.NewBIGint(d)
		dExp.Invmodp(BN254.NewBIGints(BN254.CURVE_Order)) // d^-1
		yAp = BN254.G1mul(yAp, dExp)

		// decrypt message: m = c0 * e(x'*y', C1)^-1 * e(C2*C3^(d-1), z)
		xAp2 := BN254.NewECP()
		xAp2.Copy(xAp)
		xAp2.Add(yAp) // x' * y'

		e1 := BN254.Ate(cipher.c1, xAp2)
		e1 = BN254.Fexp(e1)
		e1.Inverse() // e(x'*y', C1)^-1

		c3Ap := BN254.G1mul(cipher.c3, dExp)
		c2Ap := BN254.NewECP()
		c2Ap.Copy(cipher.c2)
		c2Ap.Add(c3Ap) // C2*C3^(d-1)

		e2 := BN254.Ate(secKey.z, c2Ap)
		e2 = BN254.Fexp(e2) // e(C2*C3^(d-1), z)

		mes = BN254.NewFP12copy(cipher.c0)
		mes.Mul(e1)
		mes.Mul(e2) // m

	} else {
		err = errors.New("ERROR: d = 0, your ID is part of the revoked set!")
	}
	return mes, err
}

//-----Helper Functions
// check if slice contains element
func contains(is []int, in int) bool {
	for i := 0; i < len(is); i++ {
		if is[i] == in {
			return true
		}
	}
	return false
}

// get index for specific element in slice
func getIndex(s int, sl []int) int {
	for key, val := range sl {
		if s == val {
			return key
		}
	}
	return -1
}

// Initialise the Random Number Generator
// call only once at beginning of program!
func initRNG() {
	var raw [128]byte

	// non-fixed seed
	seed := rand.NewSource(time.Now().UnixNano())
	r := rand.New(seed)

	// rng from MIRACL Core Rand.go
	rng = core.NewRAND()
	rng.Clean()

	// use non-fixed seed and generator from math/rand to create seed for rng
	for i := 0; i < 128; i++ {
		raw[i] = byte(r.Intn(255))
	}

	rng.Seed(128, raw[:]) // seed rng
}
