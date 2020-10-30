package main

import (
	"fmt"
	"time"

	"github.com/miracl/core/go/core/BN254"
)

func main() {

	// measure time of algorithms
	init := time.Now()

	// Initialise Random number generator
	initRNG()

	// Specify ID, CL and RL
	id := "0110"                         // User's ID
	s := &subset{cl: "***0", rl: "*100"} // subset consisting of CL and RL
	l := len(id)                         // ID bit length

	// TODO - if id is not part of cl or part of rl, the program throws runtime error nil pointer exception -> make sure program simply stops with error message and does not go on!

	// Print ID,CL,RL

	// Print all Setup-related Parameters
	pubKey, mk := setup(l)
	printSetup(pubKey, mk, l)

	// Print all KeyGen-related Parameters
	secKey := keyGen(id, mk, pubKey)
	printKeyGen(secKey, l)

	// Create random message M in GT
	message := createRandomM(pubKey)

	// // Print message
	// fmt.Println("original message: ", message.ToString())

	// Call Encrypt
	cipher := encrypt(s, pubKey, message)
	printEncrypt(cipher)

	mes := decrypt(s, id, secKey, cipher)

	functional := message.Equals(mes) // test if encrypted message is same as decrypted message
	fmt.Println("\n")
	fmt.Println("Message is same: ", functional)

	// fmt.Println(x0, y0, xelements, yEven, yOdd, z, c0, c1, c2, c3)

	// end of stopwatch
	fmt.Println("\n")
	elapsed := time.Since(init)
	fmt.Printf("Binomial took %s", elapsed)

	// Check Validity of all Parameters
	testValidity(pubKey, mk, message)

}

// Function to print all setup related parameters
func printSetup(pubkey *pk, mk *BN254.ECP, l int) {

	q := BN254.NewBIGints(BN254.CURVE_Order)

	fmt.Println("\n")
	fmt.Println("-------  SETUP  ---------")
	fmt.Printf("P:\t%s\n", pubkey.p.ToString())
	fmt.Printf("Q:\t%s\n", q.ToString())
	fmt.Println("g1: ", pubkey.g1.ToString(), "")
	fmt.Println("g2: ", pubkey.g2.ToString(), "")

	fmt.Printf("h_0 = %s\n", pubkey.h0.ToString())
	for i := 0; i < l; i++ {
		fmt.Printf("h_%d,0 = %s\n", i+1, pubkey.helements0[i].ToString())
		fmt.Printf("h_%d,1 = %s\n", i+1, pubkey.helements1[i].ToString())
	}
	fmt.Println("\n")

	fmt.Printf("k_0 = %s\n", pubkey.k0.ToString())
	for i := 0; i < l; i++ {
		fmt.Printf("k_%d,0 = %s\n", i+1, pubkey.kelements0[i].ToString())
		fmt.Printf("k_%d,1 = %s\n", i+1, pubkey.kelements1[i].ToString())
	}
}

// Function to print all keygen related parameters
func printKeyGen(secKey *sk, l int) {

	fmt.Println("\n\n")
	fmt.Println("-------  KeyGen  ---------")

	fmt.Println("x0: ", secKey.x0.ToString(), "")
	for i := 0; i < l; i++ {
		fmt.Println("x", i+1, ":", secKey.xelements[i].ToString())
	}
	fmt.Println("y0: ", secKey.y0.ToString(), "")

	for i := 0; i < l; i++ {
		fmt.Println("y", (i+1)*2-1, ":", secKey.yOdd[i].ToString())
		fmt.Println("y", (i+1)*2, ":", secKey.yEven[i].ToString())
	}

}

// Function to print all encrypt related parameters
func printEncrypt(cipher *hdr) {

	fmt.Println("\n\n")
	fmt.Println("-------  Encrypt  ---------")

	fmt.Println("c0 : ", cipher.c0.ToString())
	fmt.Println("c1 : ", cipher.c1.ToString())
	fmt.Println("c2 : ", cipher.c2.ToString())
	fmt.Println("c3 : ", cipher.c3.ToString())

}

// Function to print all decrypt related parameters
func printDecrypt() {
	fmt.Println("\n\n")
	fmt.Println("-------  Decrypt  ---------")
}

// Function to test if all points are really valid
// i.e. g1 in G1 etc.
func testValidity(pubkey *pk, mk *BN254.ECP, message *BN254.FP12) {

	fmt.Println("\n\n")
	fmt.Println("-------  Validity Test  ---------")

	fmt.Println("Is g1 really in G1? ", BN254.G1member(pubkey.g1))
	fmt.Println("Is g2 really in G2? ", BN254.G2member(pubkey.g2))
	fmt.Println("Is MK a point in G1? - ", BN254.G1member(mk))

	val := BN254.GTmember(message)
	fmt.Println("Is message is GT member? ", val)

}
