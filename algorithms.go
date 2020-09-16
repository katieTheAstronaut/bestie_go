package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/miracl/core/go/core"
	"github.com/miracl/core/go/core/BN254"
)

// Function to Initialise the Random Number Generator (call only once at beginning of program!!!)
// Since the curve order defines how many unique curve points there are, to get a random point (by multiplying the generator and alpha) we need alpha to be a random number between 1 and the curve order q, as such we use q as the modulus in Randomnum()
// rng is a random number generator - here we can use the rng from Rand.go
// In order to instantiate rng, we also need a seed as source for the randomness. This seed should typically be a non-fixed seed, as we will otherwise get the same output every time. Hence we use time.Now().UnixNano() --> see https://golang.org/pkg/math/rand/ for more info -> we'll use package math/rand for this, using its generator and the non-fixed seed to create the seed for our core rng.
func initRNG() *core.RAND {
	var raw [128]byte

	seed := rand.NewSource(time.Now().UnixNano())
	r := rand.New(seed)

	rng := core.NewRAND()
	rng.Clean()

	// TODO - check if this is truly non-deterministic!
	for i := 0; i < 128; i++ {
		raw[i] = byte(r.Intn(255)) // 255 as that is the largest number that can be stored in a byte!
	}

	rng.Seed(128, raw[:])
	return rng
}

// ----------- (Global) Parameters
// TODO - do we want global parameters?
var l = 3 // ID bit Length

// Setup takes l -
// TODO: what about lambda? Does it make sense in this implementation via curve?
func setup(l int, rng *core.RAND) (p *BN254.BIG, g1 *BN254.ECP, g2 *BN254.ECP2, h0, k0 *BN254.ECP, helements0, helements1, kelements0, kelements1 []*BN254.ECP, omega *BN254.FP12, mk *BN254.ECP, alpha *BN254.BIG) {
	// ----------- Setup 1
	// 1. Generate bilinear groups of order p
	// - already done once you chose the curve
	// TODO - Make setup "generic" by using different curves --> write a getParameter func for each curve
	p = BN254.NewBIGints(BN254.Modulus)
	q := BN254.NewBIGints(BN254.CURVE_Order) // TODO - maybe call this r

	// ----------- Setup 2
	// 2. Select two random elements g1 in G1 and g2 in G2
	// note, these have to be generators, to make sure that we receive valid points on the curve, if we multiply with these points
	g1 = BN254.ECP_generator()
	g2 = BN254.ECP2_generator()

	// ----------- Setup 3
	// 3. Select random exponent alpha in Zp --> q needs to be modulus though!
	alpha = BN254.Randomnum(q, rng)

	// ----------- Setup 4
	// 4. Select random group elements
	// h0 is single variable,
	// h1,0 ... hl,0 and h1,1 ... hl,1 are two separate slices (even and odd) to make this more readable!
	h0Rand := BN254.Randomnum(q, rng)
	h0 = BN254.G1mul(g1, h0Rand)

	hrands0 := make([]*BN254.BIG, l)   // slice for random numbers h1,0 ... hl,0
	helements0 = make([]*BN254.ECP, l) // Slice for resulting random group elements of G1
	for i := 0; i < l; i++ {
		hrands0[i] = BN254.Randomnum(q, rng)
		helements0[i] = BN254.G1mul(g1, hrands0[i])
	}

	hrands1 := make([]*BN254.BIG, l)   // slice for random numbers h1,1 ... hl,1
	helements1 = make([]*BN254.ECP, l) // Slice for resulting random group elements of G1
	for i := 0; i < l; i++ {
		hrands1[i] = BN254.Randomnum(q, rng)
		helements1[i] = BN254.G1mul(g1, hrands1[i])
	}

	// k0, ... kl,1 in G1
	k0Rand := BN254.Randomnum(q, rng)
	k0 = BN254.G1mul(g1, k0Rand)

	krands0 := make([]*BN254.BIG, l)   // slice for random numbers
	kelements0 = make([]*BN254.ECP, l) // Slice for resulting random group elements of G1
	for i := 0; i < l; i++ {
		krands0[i] = BN254.Randomnum(q, rng)
		kelements0[i] = BN254.G1mul(g1, krands0[i])
	}

	krands1 := make([]*BN254.BIG, l)   // slice for random numbers
	kelements1 = make([]*BN254.ECP, l) // Slice for resulting random group elements of G1
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
	omega = BN254.Ate(g2, g1)
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

	fmt.Printf("h_0 = %s\n", h0.ToString())
	fmt.Printf("k_0 = %s\n", k0.ToString())
	for i := 0; i < l; i++ {
		fmt.Printf("h_%d,0 = %s\n", i+1, helements0[i].ToString())
		fmt.Printf("h_%d,1 = %s\n", i+1, helements1[i].ToString())
		fmt.Printf("k_%d,0 = %s\n", i+1, kelements0[i].ToString())
		fmt.Printf("k_%d,1 = %s\n", i+1, kelements1[i].ToString())

		// val := BN254.G1member(helements[1])
		// fmt.Println("Is Point member of G1? ", val, " ")
	}

	// for i := 0; i < 2*l+1; i++ {
	// 	value2 := krands[i].ToString()
	// 	if i == 0 {
	// 		fmt.Printf("k_%d = %s\n", i, value2)
	// 		fmt.Println(kelements[i])
	// 	} else if i%2 == 0 {
	// 		fmt.Printf("k_%d,%d = %s\n", i/2, 1, value2)
	// 		fmt.Println(kelements[i])
	// 	} else {
	// 		fmt.Printf("k_%d,%d = %s\n", (i+1)/2, 0, value2)
	// 		fmt.Println(kelements[i])
	// 	}
	// 	val := BN254.G1member(kelements[1])
	// 	fmt.Println("Is Point member of G1? ", val, " ")
	// }
	return p, g1, g2, h0, k0, helements0, helements1, kelements0, kelements1, omega, mk, alpha
}

// KeyGen takes user's ID, master key, and public parameters
func keyGen(id string, mk *BN254.ECP, p *BN254.BIG, g1 *BN254.ECP, g2 *BN254.ECP2, h0, k0 *BN254.ECP, helements0, helements1, kelements0, kelements1 []*BN254.ECP, omega *BN254.FP12, rng *core.RAND, alpha *BN254.BIG) (x0, y0 *BN254.ECP, xelements, yEven, yOdd []*BN254.ECP, z *BN254.ECP2) {

	fmt.Println("\n\n")
	fmt.Println("-------  KeyGen  ---------")
	fmt.Println("The ID is: ", id, "")

	q := BN254.NewBIGints(BN254.CURVE_Order) // TODO - do not repeat yourself, consider putting this in main? but it needs to be secret

	// ----------- KeyGen 1
	// 1. Select two random exponents alpha_omega and r in Zp
	alphaOmega := BN254.Randomnum(q, rng)
	r := BN254.Randomnum(q, rng)

	// ----------- KeyGen 2
	// Create private key SK_ID

	// ---x0
	exp := alpha.Minus(alphaOmega)
	g1AlphaMinOmega := BN254.G1mul(g1, exp) // g1^(alpha-alphaOmega)

	hID := BN254.NewECP()

	// while BESTIE construction theoretically notes to multiply points, in EC this means we need to add all the points of h (point addition)
	// TODO - this is ridiculously ugly, rewrite this code!
	for i := 0; i < l; i++ {
		if string(id[i]) == "0" {
			hID.Add(helements0[i])
			fmt.Println(" h_", i+1, "IDi : ", helements0[i].ToString(), " ")
		} else if string(id[i]) == "1" {
			hID.Add(helements1[i])
			fmt.Println(" h_", i+1, "IDi : ", helements1[i].ToString(), " ")
		} else {
			fmt.Println("ID could not be read")
		}

	}
	hID.Add(h0)
	hExp := BN254.G1mul(hID, r)
	hExp.Add(g1AlphaMinOmega)

	x0 = hExp
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

	xelements = make([]*BN254.ECP, l) // make a slice for x1 to xl

	for i := 0; i < l; i++ {
		if string(id[i]) == "0" { // TODO - perhaps make this more elegant and turn ID into slice instead of string? Then we wouldnt have to convert from string byte (string behaves like slice here) to string to compare both
			xelements[i] = BN254.G1mul(helements1[i], r)
			fmt.Println(" x ", i+1, " : ", xelements[i].ToString(), " ")
		} else if string(id[i]) == "1" {
			xelements[i] = BN254.G1mul(helements0[i], r)
			fmt.Println(" x ", i+1, " : ", xelements[i].ToString(), " ")
		} else {
			fmt.Println("ID could not be read")
		}
	}

	// -- y0

	y0 = BN254.G1mul(k0, r)
	fmt.Println(y0)

	// -- y1...y2l
	// two slices of odd and even, to make is more readable
	// y1,y3,...
	g1AlphaOmega := BN254.G1mul(g1, alphaOmega) // g1^alphaOmega
	yOdd = make([]*BN254.ECP, l)
	yEven = make([]*BN254.ECP, l)

	for i := 0; i < l; i++ {
		if string(id[i]) == "0" { // TODO - perhaps make this more elegant and turn ID into slice instead of string? Then we wouldnt have to convert from string byte (string behaves like slice here) to string to compare both
			temp := BN254.G1mul(kelements1[i], r)
			temp.Add(g1AlphaOmega)
			yOdd[i] = temp
			yEven[i] = kelements0[i]
			fmt.Println(" y_", (i+1)*2-1, " : ", yOdd[i].ToString(), " ")
			fmt.Println(" y_", (i+1)*2, " : ", yEven[i].ToString(), " ")
		} else if string(id[i]) == "1" {
			temp := BN254.G1mul(kelements0[i], r)
			temp.Add(g1AlphaOmega)
			yOdd[i] = temp
			yEven[i] = kelements1[i]
			fmt.Println(" y_", (i+1)*2-1, " : ", yOdd[i].ToString(), " ")
			fmt.Println(" y_", (i+1)*2, " : ", yEven[i].ToString(), " ")
		} else {
			fmt.Println("issue")
		}
	}

	// z
	z = BN254.G2mul(g2, r)

	// return private key
	return x0, y0, xelements, yEven, yOdd, z
}

// Encrypt takes subset (covered list CL and revoked list RL), public key parameters, and message m
func encrypt(cl, rl string, p *BN254.BIG, g1 *BN254.ECP, g2 *BN254.ECP2, h0, k0 *BN254.ECP, helements0, helements1, kelements0, kelements1 []*BN254.ECP, omega *BN254.FP12, message *BN254.FP12, rng *core.RAND) {

	q := BN254.NewBIGints(BN254.CURVE_Order) // TODO - do not repeat yourself, consider putting this in main? but it needs to be secret

	// ----------- Encrypt 1
	// Select random exponent t in Zp
	t := BN254.Randomnum(q, rng)

	// ----------- Encrypt 1
	// Return ciphertext Hdr

	// Hdr_S = (C0, C1, C2 C3)

	// C0 = omega^t * M (both GT elements)
	c0 := omega.Pow(t)
	c0.Mul(message)

	// c1 = g2^t
	c1 := BN254.G2mul(g2, t)

	// c2 = H(CL)^t
	hcl := BN254.NewECP()
	hcl.Add(helements1[0])

	// for i:= 0; i<l; i++ {
	// 	hcl[i] =
	// }

	fmt.Println("hcl should be same as:", hcl)
	fmt.Println("h1,1:", helements1[0])

	fmt.Println("c0 : ", c0)
	fmt.Println("Message: ", message.ToString())
	fmt.Println("c1 : ", c1)

}

func main() {

	// measure time of algorithms
	init := time.Now()

	// Initialise Random number generator
	rng := initRNG()

	// Call Setup to get public parameters
	// pass rng as parameter, so we only need to initialise it once in main
	p, g1, g2, h0, k0, helements0, helements1, kelements0, kelements1, omega, mk, alpha := setup(l, rng)

	// Call KeyGen to generate private key
	// TODO - try this for several users later
	// TODO - link id to l
	id := "010" // User's ID

	// Call KeyGen to get private key SK (parameters)
	// TODO - get mk and alpha from setup (through other func/package?)
	x0, y0, xelements, yEven, yOdd, z := keyGen(id, mk, p, g1, g2, h0, k0, helements0, helements1, kelements0, kelements1, omega, rng, alpha)

	// Create message M in GT
	q := BN254.NewBIGints(BN254.CURVE_Order)
	// TODO - remove q, as it needs to stay secret?
	// TODO - this is wrong!!!, but for now we will use a random GT element as message
	rand1 := BN254.Randomnum(q, rng)
	m1 := BN254.G1mul(g1, rand1)
	rand2 := BN254.Randomnum(q, rng)
	m2 := BN254.G2mul(g2, rand2)
	message := BN254.Ate(m2, m1)
	message = BN254.Fexp(message)
	val := BN254.GTmember(message)
	fmt.Println("message is GT member: ", val)

	// CL
	cl := "**1*"
	rl := "*011"
	// Call Encrypt
	encrypt(cl, rl, p, g1, g2, h0, k0, helements0, helements1, kelements0, kelements1, omega, message, rng)

	fmt.Println(x0, y0, xelements, yEven, yOdd, z)

	// end of stopwatch
	elapsed := time.Since(init)
	fmt.Printf("Binomial took %s", elapsed)

}
