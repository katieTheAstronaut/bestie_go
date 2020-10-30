package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/miracl/core/go/core"
	"github.com/miracl/core/go/core/BN254"
)

// ----------- Structs

type pk struct { // TODO - groups g1,g2,gt and e are missing, how do we put them in here?
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

func setup(l int) (pubKey *pk, mk *BN254.ECP) {
	// ----------- Setup 1
	// 1. Generate bilinear groups of order p
	// - already done once you chose the curve
	p := BN254.NewBIGints(BN254.Modulus)
	q := BN254.NewBIGints(BN254.CURVE_Order) // TODO - maybe call this r

	// ----------- Setup 2
	// 2. Select two random elements g1 in G1 and g2 in G2
	// note, these have to be generators, to make sure that we receive valid points on the curve, if we multiply with these points
	g1 := BN254.ECP_generator()
	g2 := BN254.ECP2_generator()

	// ----------- Setup 3
	// 3. Select random exponent alpha in Zp --> q needs to be modulus though!
	alpha := BN254.Randomnum(q, rng)

	// ----------- Setup 4
	// 4. Select random group elements
	// h0 is single variable,
	// h1,0 ... hl,0 and h1,1 ... hl,1 are two separate slices (even and odd) to make this more readable!
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

	// k0, ... kl,1 in G1
	k0Rand := BN254.Randomnum(q, rng)
	k0 := BN254.G1mul(g1, k0Rand)

	krands0 := make([]*BN254.BIG, l)    // slice for random numbers
	kelements0 := make([]*BN254.ECP, l) // Slice for resulting random group elements of G1
	for i := 0; i < l; i++ {
		krands0[i] = BN254.Randomnum(q, rng)
		kelements0[i] = BN254.G1mul(g1, krands0[i])
	}

	krands1 := make([]*BN254.BIG, l)    // slice for random numbers
	kelements1 := make([]*BN254.ECP, l) // Slice for resulting random group elements of G1
	for i := 0; i < l; i++ {
		krands1[i] = BN254.Randomnum(q, rng)
		kelements1[i] = BN254.G1mul(g1, krands1[i])
	}

	// ----------- Setup 5
	// 5. Return secret master key MK = g1^alpha
	mk = BN254.G1mul(g1, alpha)

	// ----------- Setup 6
	// 6. Return Public Key / Public Parameters

	// compute pairing Omega = e(g1,g2)^alpha
	omega := BN254.Ate(g2, g1)
	omega = BN254.Fexp(omega)
	omega = omega.Pow(alpha)

	pubKey = &pk{p, g1, g2, h0, k0, helements0, helements1, kelements0, kelements1, omega}

	return pubKey, mk
}

// KeyGen takes user's ID, master key, and public parameters
func keyGen(id string, mk *BN254.ECP, pubKey *pk) (secKey *sk) {

	q := BN254.NewBIGints(BN254.CURVE_Order) // TODO - do not repeat yourself, consider putting this in main? but it needs to be secret
	l := len(id)
	// ----------- KeyGen 1
	// 1. Select two random exponents alpha_omega and r in Zp
	alphaOmega := BN254.Randomnum(q, rng)
	r := BN254.Randomnum(q, rng)

	// ----------- KeyGen 2
	// Create private key SK_ID

	// ---x0
	//// g1^(alpha-alphaOmega) = mk / mk2

	mk2 := BN254.G1mul(pubKey.g1, alphaOmega) // mk2 =  g1^alphaOmega
	g1AlphaMinOmega := BN254.NewECP()
	g1AlphaMinOmega.Copy(mk)

	g1AlphaOmega := BN254.NewECP()
	g1AlphaOmega.Copy(mk2)
	g1AlphaOmega.Neg()                // compute mk2^-1
	g1AlphaMinOmega.Add(g1AlphaOmega) // mk * mk2^-1

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
	hExp.Add(g1AlphaMinOmega)

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
	//// two slices of odd and even, to make is more readable
	yOdd := make([]*BN254.ECP, l)
	yEven := make([]*BN254.ECP, l)

	for i := 0; i < l; i++ {
		if string(id[i]) == "0" {
			temp := BN254.G1mul(pubKey.kelements1[i], r)
			temp.Add(mk2)
			yOdd[i] = temp
			temp2 := BN254.G1mul(pubKey.kelements0[i], r)
			yEven[i] = temp2
		} else if string(id[i]) == "1" {
			temp := BN254.G1mul(pubKey.kelements0[i], r)
			temp.Add(mk2)
			yOdd[i] = temp
			temp2 := BN254.G1mul(pubKey.kelements1[i], r)
			yEven[i] = temp2
		} else {
			fmt.Println("ID could not be read")
		}
	}

	// z
	z := BN254.G2mul(pubKey.g2, r)

	secKey = &sk{x0, xelements, y0, yEven, yOdd, z}

	// return private key
	return secKey
}

// Encrypt takes subset (covered list CL and revoked list RL), public key parameters, and message m
func encrypt(s *subset, pubKey *pk, message *BN254.FP12) (cipher *hdr) {

	q := BN254.NewBIGints(BN254.CURVE_Order) // TODO - do not repeat yourself, consider putting this in main? but it needs to be secret
	l := len(s.cl)

	// ----------- Encrypt 1
	// Select random exponent t in Zp
	t := BN254.Randomnum(q, rng)

	// ----------- Encrypt 1
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

// Decrypt takes subset, user's ID, private key SK_ID, and ciphertext HdrS and returns message M
func decrypt(s *subset, id string, secKey *sk, cipher *hdr) (mes *BN254.FP12) {

	q := BN254.NewBIGints(BN254.CURVE_Order) // TODO - do not repeat yourself, consider putting this in main? but it needs to be secret
	l := len(id)

	// compute P = bits that are different from revoked list
	// note:  the set of all indexes of ID, where the ID is not equal to the revoked set and the revoked set is not a wildcard

	pRl := []int{} // empty slice

	for i := 0; i < l; i++ {
		if string(s.rl[i]) != "*" && id[i] != s.rl[i] {
			pRl = append(pRl, i+1) // we need i+1 because the scheme dictates that an ID's first index is 1, not 0
		}
	}

	// compute Q = bits that are equal to revoked set

	qRl := []int{} // empty slice

	for i := 0; i < l; i++ {
		if string(s.rl[i]) != "*" && id[i] == s.rl[i] {
			qRl = append(qRl, i+1)
		}
	}

	// compute d = number of bits in user ID that are different from RL
	d := len(pRl)

	// step 4: if d > 0, decrypt message

	if d > 0 {

		// compute x' as xAp(ostrophe)
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

		// compute d^-1
		dExp := BN254.NewBIGint(d)
		dExp.Invmodp(q)

		yAp = BN254.G1mul(yAp, dExp)

		// decrypt message: m = c0 * e(x'*y', C1)^-1 * e(C2*C3^(d-1), z)
		xAp2 := BN254.NewECP()
		xAp2.Copy(xAp)
		xAp2.Add(yAp)

		e1 := BN254.Ate(cipher.c1, xAp2)
		e1 = BN254.Fexp(e1)
		e1.Inverse() // ^-1

		c3Ap := BN254.G1mul(cipher.c3, dExp)
		c2Ap := BN254.NewECP()
		c2Ap.Copy(cipher.c2)
		c2Ap.Add(c3Ap)

		e2 := BN254.Ate(secKey.z, c2Ap)
		e2 = BN254.Fexp(e2)

		mes = BN254.NewFP12copy(cipher.c0)
		mes.Mul(e1)
		mes.Mul(e2)

	} else {
		fmt.Println("error: d = ", d, "the ID is part of the revoked set!")
	}

	return mes
}

//-----Helper Functions

func contains(is []int, in int) bool {
	for i := 0; i < len(is); i++ {
		if is[i] == in {
			return true
		}
	}
	return false
}

func getIndex(s int, sl []int) int {
	for key, val := range sl {
		if s == val {
			return key
		}
	}
	return -1
}

// Function to Initialise the Random Number Generator (call only once at beginning of program!!!)
// Since the curve order defines how many unique curve points there are, to get a random point (by multiplying the generator and alpha) we need alpha to be a random number between 1 and the curve order q, as such we use q as the modulus in Randomnum()
// rng is a random number generator - here we can use the rng from Rand.go
// In order to instantiate rng, we also need a seed as source for the randomness. This seed should typically be a non-fixed seed, as we will otherwise get the same output every time. Hence we use time.Now().UnixNano() --> see https://golang.org/pkg/math/rand/ for more info -> we'll use package math/rand for this, using its generator and the non-fixed seed to create the seed for our core rng.
func initRNG() {
	var raw [128]byte

	seed := rand.NewSource(time.Now().UnixNano())
	r := rand.New(seed)

	rng = core.NewRAND()
	rng.Clean()

	// TODO - check if this is truly non-deterministic!
	for i := 0; i < 128; i++ {
		raw[i] = byte(r.Intn(255)) // 255 as that is the largest number that can be stored in a byte!
	}

	rng.Seed(128, raw[:])
}
