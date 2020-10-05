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

// ----------- Package Scope (global) Variables
var rng *core.RAND

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

// Setup takes l -
// TODO: what about lambda? Does it make sense in this implementation via curve?
func setup(l int) (pubKey *pk, mk *BN254.ECP, alpha *BN254.BIG) {
	// ----------- Setup 1
	// 1. Generate bilinear groups of order p
	// - already done once you chose the curve
	// TODO - Make setup "generic" by using different curves --> write a getParameter func for each curve
	p := BN254.NewBIGints(BN254.Modulus)
	q := BN254.NewBIGints(BN254.CURVE_Order) // TODO - maybe call this r

	// ----------- Setup 2
	// 2. Select two random elements g1 in G1 and g2 in G2
	// note, these have to be generators, to make sure that we receive valid points on the curve, if we multiply with these points
	g1 := BN254.ECP_generator()
	g2 := BN254.ECP2_generator()

	// ----------- Setup 3
	// 3. Select random exponent alpha in Zp --> q needs to be modulus though!
	alpha = BN254.Randomnum(q, rng)

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
	// note: In BESTIE, the groups in the pairings are written as multiplicative groups. However, g1^alpha really represents a multiplikation of g1 * alpha

	mk = BN254.G1mul(g1, alpha)
	// TODO - work with different packages, so that mk can be called by keygen function, needs to be secret

	// ----------- Setup 6
	// 6. Return Public Key / Public Parameters
	// Note, we cannot return the bilinear group (p,G1,G2,GT,e) here, as these are merely available by using the same curve. But by using the same curve in the other algorithms, there parameters are available anyways --> are these then still secure?

	// TODO - this really only makes sense here if we work with different functions or even packages, so that decrypt cannot access any keys that are not within these PK parameters

	// compute pairing Omega = e(g1,g2)^alpha
	omega := BN254.Ate(g2, g1)
	omega = BN254.Fexp(omega)
	omega = omega.Pow(alpha)

	// Test if pairing pow works, i.e. test if e(g1,g2)^alpha is same as e(g1^alpha,g2) --> works!
	// omegatest := BN254.Ate(g2, mk)
	// omegatest = BN254.Fexp(omegatest)

	// fmt.Println("Omega: ", omega.ToString(), "")
	// fmt.Println("Omegatest: ", omegatest.ToString(), "")
	// fmt.Println(omega.Equals(omegatest))

	// ----------- Print Stuff / Test
	fmt.Println("\n\n")
	fmt.Println("-------  SETUP  ---------")
	// fmt.Println("The Modulus p is: (", p, ")")
	// fmt.Printf("P:\t%s\n", p.ToString())
	// fmt.Println(new(big.Int).SetString(p.ToString(), 16))
	// fmt.Println("The Curve Order q(or r) is: (", q, ")")
	// fmt.Printf("Q:\t%s\n", q.ToString())
	// fmt.Println(new(big.Int).SetString(q.ToString(), 16))
	// fmt.Println("\n\n")
	// fmt.Println("The Point G1: ", g1, "")
	// fmt.Println("The Point G2: ", g2, "")
	// fmt.Println("The random exponent alpha: ", alpha, " \n")

	// fmt.Println("Master Key (secret): ", mk, " - is this a point in G1? - ", BN254.G1member(mk), " ")

	//
	// Printing Parameters
	fmt.Printf("h_0 = %s\n", h0.ToString())
	for i := 0; i < l; i++ {
		fmt.Printf("h_%d,0 = %s\n", i+1, helements0[i].ToString())
		fmt.Printf("h_%d,1 = %s\n", i+1, helements1[i].ToString())
	}
	fmt.Println("\n")

	fmt.Printf("k_0 = %s\n", k0.ToString())
	for i := 0; i < l; i++ {
		fmt.Printf("k_%d,0 = %s\n", i+1, kelements0[i].ToString())
		fmt.Printf("k_%d,1 = %s\n", i+1, kelements1[i].ToString())
	}

	pubKey = &pk{p, g1, g2, h0, k0, helements0, helements1, kelements0, kelements1, omega}

	return pubKey, mk, alpha
}

// KeyGen takes user's ID, master key, and public parameters
func keyGen(id string, mk *BN254.ECP, pubKey *pk, alpha *BN254.BIG) (secKey *sk, r *BN254.BIG, g1AlphaMinOmega, g1AlphaOmega *BN254.ECP) {

	fmt.Println("\n\n")
	fmt.Println("-------  KeyGen  ---------")
	fmt.Println("The ID is: ", id, "")

	q := BN254.NewBIGints(BN254.CURVE_Order) // TODO - do not repeat yourself, consider putting this in main? but it needs to be secret
	l := len(id)
	// ----------- KeyGen 1
	// 1. Select two random exponents alpha_omega and r in Zp
	alphaOmega := BN254.Randomnum(q, rng)
	r = BN254.Randomnum(q, rng)

	// ----------- KeyGen 2
	// Create private key SK_ID

	// ---x0
	exp := alpha.Minus(alphaOmega)
	g1AlphaMinOmega = BN254.G1mul(pubKey.g1, exp) // g1^(alpha-alphaOmega)

	hID := BN254.NewECP()
	hID.Copy(pubKey.h0) // deep copy of ECP via ECP.Copy() method

	// while BESTIE construction theoretically notes to multiply points, in EC this means we need to add all the points of h (point addition)
	// TODO - this is ridiculously ugly, rewrite this code!
	for i := 0; i < l; i++ {
		if string(id[i]) == "0" {
			hID.Add(pubKey.helements0[i])
			fmt.Println(" h_", i+1, "IDi : ", pubKey.helements0[i].ToString(), " ")
		} else if string(id[i]) == "1" {
			hID.Add(pubKey.helements1[i])
			fmt.Println(" h_", i+1, "IDi : ", pubKey.helements1[i].ToString(), " ")
		} else {
			fmt.Println("ID could not be read")
		}

	}

	hExp := BN254.G1mul(hID, r)
	hExp.Add(g1AlphaMinOmega)

	x0 := hExp
	fmt.Println("x0 is the point: ", x0.ToString(), "")

	// Test if adding the points for ID 010 will give the same resulting point --> it will
	// x0Test := helements[1]
	// x0Test.Add(helements[4])
	// x0Test.Add(helements[5])
	// x0Test.Add(helements[0])
	// hExpTest := BN254.G1mul(x0Test, r)
	// hExpTest.Add(g1AlphaMinOmega)

	// fmt.Println("x0Test is the point: ", hExpTest.ToString(), "")

	// ---x1 - xl

	xelements := make([]*BN254.ECP, l) // make a slice for x1 to xl

	for i := 0; i < l; i++ {
		if string(id[i]) == "0" {
			xelements[i] = BN254.G1mul(pubKey.helements1[i], r)
			fmt.Println(" x ", i+1, " : ", xelements[i].ToString(), " ")
		} else if string(id[i]) == "1" {
			xelements[i] = BN254.G1mul(pubKey.helements0[i], r)
			fmt.Println(" x ", i+1, " : ", xelements[i].ToString(), " ")
		} else {
			fmt.Println("ID could not be read")
		}
	}

	// -- y0

	y0 := BN254.G1mul(pubKey.k0, r)
	fmt.Println("y0 is the point: ", y0.ToString(), "")

	// -- y1...y2l
	// two slices of odd and even, to make is more readable
	// y1,y3,...
	g1AlphaOmega = BN254.G1mul(pubKey.g1, alphaOmega) // g1^alphaOmega
	yOdd := make([]*BN254.ECP, l)
	yEven := make([]*BN254.ECP, l)

	for i := 0; i < l; i++ {
		if string(id[i]) == "0" { // TODO - perhaps make this more elegant and turn ID into slice instead of string? Then we wouldnt have to convert from string byte (string behaves like slice here) to string to compare both
			temp := BN254.G1mul(pubKey.kelements1[i], r)
			temp.Add(g1AlphaOmega)
			yOdd[i] = temp
			temp2 := BN254.G1mul(pubKey.kelements0[i], r)
			yEven[i] = temp2
			fmt.Println(" y_", (i+1)*2-1, " : ", yOdd[i].ToString(), " ")
			fmt.Println(" y_", (i+1)*2, " : ", yEven[i].ToString(), " ")
		} else if string(id[i]) == "1" {
			temp := BN254.G1mul(pubKey.kelements0[i], r)
			temp.Add(g1AlphaOmega)
			yOdd[i] = temp
			temp2 := BN254.G1mul(pubKey.kelements1[i], r)
			yEven[i] = temp2
			fmt.Println(" y_", (i+1)*2-1, " : ", yOdd[i].ToString(), " ")
			fmt.Println(" y_", (i+1)*2, " : ", yEven[i].ToString(), " ")
		} else {
			fmt.Println("issue")
		}
	}

	// z
	z := BN254.G2mul(pubKey.g2, r)

	secKey = &sk{x0, xelements, y0, yEven, yOdd, z}

	// return private key
	return secKey, r, g1AlphaMinOmega, g1AlphaOmega
}

// Encrypt takes subset (covered list CL and revoked list RL), public key parameters, and message m
func encrypt(cl, rl string, pubKey *pk, message *BN254.FP12, r *BN254.BIG, g1AlphaMinOmega *BN254.ECP) (cipher *hdr, krl *BN254.ECP) {

	fmt.Println("\n\n")
	fmt.Println("-------  Encrypt  ---------")

	q := BN254.NewBIGints(BN254.CURVE_Order) // TODO - do not repeat yourself, consider putting this in main? but it needs to be secret
	l := len(cl)
	// ----------- Encrypt 1
	// Select random exponent t in Zp
	t := BN254.Randomnum(q, rng)

	// ----------- Encrypt 1
	// Return ciphertext Hdr

	// Hdr_S = (C0, C1, C2 C3)

	// C0 = omega^t * M (both GT elements)
	c0 := pubKey.omega.Pow(t)
	c0.Mul(message)

	// c1 = g2^t
	c1 := BN254.G2mul(pubKey.g2, t)

	// c2 = H(CL)^t
	hcl := BN254.NewECP()
	hcl.Copy(pubKey.h0) // deep copy of ECP via ECP.Copy() method

	fmt.Println("CL : ", cl)
	for i := 0; i < l; i++ {
		if string(cl[i]) == "0" {
			hcl.Add(pubKey.helements0[i])
			fmt.Println("h_", i+1, "CLi : ", pubKey.helements0[i].ToString(), " ")
		} else if string(cl[i]) == "1" {
			hcl.Add(pubKey.helements1[i])
			fmt.Println("h_", i+1, "CLi : ", pubKey.helements1[i].ToString(), " ")
		} else if string(cl[i]) == "*" {
			hProd := BN254.NewECP()
			hProd.Copy(pubKey.helements0[i]) // deep copy of ECP via ECP.Copy() method
			hProd.Add(pubKey.helements1[i])
			hcl.Add(hProd)
			fmt.Println("h_", i+1, "CLi : ", pubKey.helements0[i].ToString(), "* ", pubKey.helements1[i].ToString())
		} else {
			fmt.Println("CL could not be read")
		}
	}

	c2 := BN254.G1mul(hcl, t)

	// c3 = K(RL)^t
	krl = BN254.NewECP()
	krl.Copy(pubKey.k0)

	fmt.Println("RL : ", rl)
	for i := 0; i < l; i++ {
		if string(rl[i]) == "0" {
			krl.Add(pubKey.kelements0[i])
			fmt.Println("k_", i+1, "_0 : ", pubKey.kelements0[i].ToString(), " ")
		} else if string(rl[i]) == "1" {
			krl.Add(pubKey.kelements1[i])
			fmt.Println("k_", i+1, "_1 : ", pubKey.kelements1[i].ToString(), " ")
		} else if string(rl[i]) == "*" {
			fmt.Println("* - Do nothing")
		} else {
			fmt.Println("RL could not be read")
		}
	}

	c3 := BN254.G1mul(krl, t)

	// fmt.Println("c0 : ", c0)
	// // fmt.Println("Message: ", message.ToString())
	// fmt.Println("c1 : ", c1)
	// fmt.Println("c2 : ", c2)
	// fmt.Println("c3 : ", c3)

	// -- Test
	hclr := BN254.G1mul(hcl, r)
	hclr.Add(g1AlphaMinOmega)
	fmt.Println("x' should be the same as g1^.. *hclr:", hclr.ToString())

	cipher = &hdr{c0, c1, c2, c3}

	// Return Ciphertext Hdr
	return cipher, krl
}

// Decrypt takes subset, user's ID, private key SK_ID, and ciphertext HdrS and returns message M
func decrypt(cl, rl, id string, secKey *sk, cipher *hdr, krl *BN254.ECP, r *BN254.BIG, g1AlphaOmega *BN254.ECP) (mes *BN254.FP12) {

	fmt.Println("\n\n")
	fmt.Println("-------  Decrypt  ---------")

	q := BN254.NewBIGints(BN254.CURVE_Order) // TODO - do not repeat yourself, consider putting this in main? but it needs to be secret
	l := len(id)
	// compute P = bits that are different from revoked list
	// note:  the set of all indexes of ID, where the ID is not equal to the revoked set and the revoked set is not a wildcard

	pRl := []int{} // empty slice

	for i := 0; i < l; i++ {
		if string(rl[i]) != "*" && id[i] != rl[i] {
			pRl = append(pRl, i+1) // we need i+1 because the scheme dictates that an ID's first index is 1, not 0
		}
	}

	// compute Q = bits that are equal to revoked set

	qRl := []int{} // empty slice

	for i := 0; i < l; i++ {
		if string(rl[i]) != "*" && id[i] == rl[i] {
			qRl = append(qRl, i+1)
		}
	}

	// compute d = number of bits in user ID that are different from RL
	d := len(pRl)

	// step 4: if d > 0, decrypt message

	fmt.Println("P: ", pRl)
	fmt.Println("Q: ", qRl)
	fmt.Println("d: ", d)

	if d > 0 {
		// TODO - if we use structs, parse struct Hdr to single fields

		// compute x' as xAp(ostrophe)
		xAp := BN254.NewECP()
		xAp.Copy(secKey.x0)
		// fmt.Println("xAp: (should be x0): ", xAp.ToString())

		for i := 0; i < l; i++ {
			if string(cl[i]) == "*" {
				xAp.Add(secKey.xelements[i])
				fmt.Println("CL at pos ", i, "is ", string(cl[i]), "so x_i is: ", secKey.xelements[i].ToString())
			}
		}
		fmt.Println("x':", xAp.ToString())

		// compute y'
		yAp := BN254.NewECP()
		yAp.Copy(secKey.y0)
		// fmt.Println("yap: ", yAp.ToString())
		for i := 1; i < l+1; i++ {
			if contains(pRl, i) {
				yAp.Add(secKey.yOdd[i-1])
				fmt.Println("p-added to yap")
				fmt.Println("P contains", i, " so y_", (2*i)-1, "is: ", secKey.yOdd[i-1].ToString())
			} else {
				// fmt.Println("p-not added to yap")
			}
		}

		// fmt.Println("yap: ", yAp.ToString())

		for i := 1; i < l+1; i++ {
			if contains(qRl, i) {
				yAp.Add(secKey.yEven[i-1])
				fmt.Println("q-added to yap")
				fmt.Println("Q contains", i, "so y_", (2 * i), "is: ", secKey.yEven[i-1].ToString())

			} else {
				// fmt.Println("q-not added to yap")

			}
		}

		// fmt.Println("y'ap_done': ", yAp.ToString())

		// compute d^-1
		dExp := BN254.NewBIGint(d)
		dExp.Invmodp(q)
		// fmt.Println("d^-1 = ", dExp.ToString())

		yAp = BN254.G1mul(yAp, dExp)

		fmt.Println("y' = ", yAp.ToString())

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

		fmt.Println("Message:", mes.ToString())

	} else {
		fmt.Println("error: d = ", d, "the ID is part of the revoked set!")
	}

	// fmt.Println("P: ", pRl)
	// fmt.Println("Q: ", qRl)
	// fmt.Println("d: ", d)

	// --- TESTING

	dExp := BN254.NewBIGint(d)
	// fmt.Println("d as Big is: ", dExp.ToString())
	dExp.Invmodp(q)
	// fmt.Println("d^-1 = ", dExp.ToString())

	krlr := BN254.G1mul(krl, r)
	fmt.Println("k(rl)^r should be the same as y0 with both points added?: ", krlr.ToString())
	krlrd := BN254.G1mul(krlr, dExp)
	krlrd.Add(g1AlphaOmega)

	fmt.Println("y' should be the same as: ", krlrd.ToString())

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

func main() {

	// measure time of algorithms
	init := time.Now()

	// Initialise Random number generator
	initRNG()

	// Call KeyGen to generate private key
	// TODO - try this for several users later
	id := "010" // User's ID
	cl := "**1" // CL - covered list of IDs
	rl := "*11" // RL - revoked list of ids

	l := len(id) // ID bit length
	// TODO - if id is not part of cl or part of rl, the program throws runtime error nil pointer exception -> make sure program simply stops with error message and does not go on!

	// Call Setup to get public parameters
	pubKey, mk, alpha := setup(l) // TODO - only pubkey should be returned here?

	// Call KeyGen to get private key SK (parameters)
	// TODO - get mk and alpha from setup (through other func/package?)
	secKey, r, g1AlphaMinOmega, g1AlphaOmega := keyGen(id, mk, pubKey, alpha)

	// Create message M in GT
	q := BN254.NewBIGints(BN254.CURVE_Order)
	// TODO - remove q, as it needs to stay secret?
	// TODO - this is wrong!!!, but for now we will use a random GT element as message
	rand1 := BN254.Randomnum(q, rng)
	m1 := BN254.G1mul(pubKey.g1, rand1)
	rand2 := BN254.Randomnum(q, rng)
	m2 := BN254.G2mul(pubKey.g2, rand2)
	message := BN254.Ate(m2, m1)
	message = BN254.Fexp(message)
	val := BN254.GTmember(message)
	fmt.Println("message is GT member: ", val)
	fmt.Println("original message: ", message.ToString())

	// Call Encrypt
	cipher, krl := encrypt(cl, rl, pubKey, message, r, g1AlphaMinOmega)

	mes := decrypt(cl, rl, id, secKey, cipher, krl, r, g1AlphaOmega)

	functional := message.Equals(mes) // test if encrypted message is same as decrypted message
	fmt.Println("\n")
	fmt.Println("Message is same: ", functional)

	// fmt.Println(x0, y0, xelements, yEven, yOdd, z, c0, c1, c2, c3)

	// end of stopwatch
	fmt.Println("\n")
	elapsed := time.Since(init)
	fmt.Printf("Binomial took %s", elapsed)

}
