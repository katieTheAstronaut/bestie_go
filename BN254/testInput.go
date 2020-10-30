package main

import "fmt"

func main() {

	// Initialise Random number generator
	initRNG()

	var id, cl, rl string

	// Get User ID
	fmt.Println("\n")
	fmt.Println("#####Welcome to BESTIE System Control######")

	fmt.Println("Please enter the list of covered IDs, e.g. **1***10*")
	fmt.Scanf("%s", &cl)

	fmt.Println("Please enter the list of revoked IDs, e.g. *****110*")
	fmt.Scanf("%s", &rl)

	fmt.Println("Please enter a device ID")
	fmt.Scanf("%s", &id)

	s := &subset{cl: cl, rl: rl} // subset consisting of CL and RL

	l := len(id) // ID bit length

	// Print ID,CL,RL
	printID(id, s)

	// Print all Setup-related Parameters
	pubKey, mk := setup(l)
	fmt.Println("\n")
	fmt.Println("--Setup done--")

	// Print all KeyGen-related Parameters
	secKey := keyGen(id, mk, pubKey)
	fmt.Println("\n")
	fmt.Println("--Secret Key for device ID generated--")

	// Create random message M in GT
	inputMessage := createRandomM(pubKey)
	fmt.Println("\n")
	fmt.Println("--Random Message generated--")
	fmt.Println("Input Message:\n ", inputMessage.ToString())

	// Call Encrypt
	cipher := encrypt(s, pubKey, inputMessage)
	fmt.Println("\n")
	fmt.Println("--Message Encrypted--")

	outputMessage, err := decrypt(s, id, secKey, cipher)
	if err != nil {
		fmt.Println("\n")
		fmt.Println("Error: ", err)
	} else {
		fmt.Println("\n")
		fmt.Println("--Message successfully Decrypted on Device--")
		fmt.Println("Output Message:\n ", outputMessage.ToString())
	}
}
