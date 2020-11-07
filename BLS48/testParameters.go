package main

import (
	"fmt"

	"github.com/miracl/core/go/core/BLS48581"
)

// func main() {

// 	// Initialise Random number generator
// 	initRNG()

// 	// Specify ID, CL and RL
// 	id := "01101010"                             // User's ID
// 	s := &subset{cl: "*1****10", rl: "*****110"} // subset consisting of CL and RL
// 	l := len(id)                                 // ID bit length

// 	// Print ID,CL,RL
// 	printID(id, s)

// 	// Print all Setup-related Parameters
// 	pubKey, mk := setup(l)
// 	printSetup(pubKey, mk, l)

// 	// Print all KeyGen-related Parameters
// 	secKey := keyGen(id, mk, pubKey)
// 	printKeyGen(secKey, l)

// 	// Create random message M in GT
// 	inputMessage := createRandomM(pubKey)

// 	// Call Encrypt
// 	cipher := encrypt(s, pubKey, inputMessage)
// 	printEncrypt(cipher, inputMessage)

// 	outputMessage, err := decrypt(s, id, secKey, cipher)
// 	printDecrypt(inputMessage, outputMessage, err)

// 	// Check Validity of all Parameters
// 	testValidity(pubKey, mk, inputMessage)

// }

func printID(id string, s *subset) {

	fmt.Println("\n")
	fmt.Println("-------  BESTIE  ---------")
	fmt.Println("Your Device ID is: ", id)
	fmt.Println("The covered IDs for this broadcast are: ", s.cl)
	fmt.Println("The revoked IDs for this broadcast are: ", s.rl)
}

// Function to print all setup related parameters
func printSetup(pubkey *pk, mk *BLS48581.ECP, l int) {

	q := BLS48581.NewBIGints(BLS48581.CURVE_Order)

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

	fmt.Println("x 0: ", secKey.x0.ToString(), "")
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
func printEncrypt(cipher *hdr, inputMessage *BLS48581.FP48) {

	fmt.Println("\n\n")
	fmt.Println("-------  Encrypt  ---------")

	fmt.Println("original message: ", inputMessage.ToString())
	fmt.Println("\n")
	fmt.Println("c0 : ", cipher.c0.ToString())
	fmt.Println("c1 : ", cipher.c1.ToString())
	fmt.Println("c2 : ", cipher.c2.ToString())
	fmt.Println("c3 : ", cipher.c3.ToString())

}

// Function to print all decrypt related parameters
func printDecrypt(inputMessage *BLS48581.FP48, outputMessage *BLS48581.FP48, err error) {

	fmt.Println("\n\n")
	fmt.Println("-------  Decrypt  ---------")

	if err != nil {
		fmt.Println(err)
	} else {
		equalMes := inputMessage.Equals(outputMessage) // test if encrypted message is same as decrypted message
		if equalMes {
			fmt.Println("Congratulations, the message was successfully decrypted")
			fmt.Println("\n")
			fmt.Println("The message is: ", outputMessage.ToString())
		} else {
			fmt.Println("ERROR: The decrypted message is not correct, your ID is not part of the covered group")
		}
	}
}

// Function to test if all points are really valid
// i.e. g1 in G1 etc.
func testValidity(pubkey *pk, mk *BLS48581.ECP, message *BLS48581.FP48) {

	fmt.Println("\n\n")
	fmt.Println("-------  Validity Test  ---------")
	fmt.Println("Is h0 really in G1? ", BLS48581.G1member(pubkey.h0))
	fmt.Println("Is g1 really in G1? ", BLS48581.G1member(pubkey.g1))
	fmt.Println("Is g2 really in G2? ", BLS48581.G2member(pubkey.g2))
	fmt.Println("Is h0 really in G1? ", BLS48581.G1member(pubkey.h0))
	fmt.Println("Is MK a point in G1? ", BLS48581.G1member(mk))
	val := BLS48581.GTmember(message)
	fmt.Println("Is message a GT member? ", val)

}
