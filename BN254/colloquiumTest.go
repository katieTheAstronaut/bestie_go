package main

import "fmt"

func main() {

	// Initialise Random number generator
	initRNG()

	var id, cl, rl string
	var l int

	fmt.Println("\n")
	fmt.Println("#####Welcome to the BESTIE System ######")
	fmt.Println("########################################")
	fmt.Println("\n")
	fmt.Println("-------  SETUP  ---------")
	fmt.Println("Please enter the ID length")
	fmt.Scanln(&l)
	fmt.Println("...Running Setup Algorithm")

	// Print all Setup-related Parameters
	pubKey, mk := setup(l)
	fmt.Println("...Setup done \u2713")
	fmt.Println("\n")
	fmt.Println("-------  KeyGen  ---------")
	// Get User ID
	fmt.Println("Please enter your device ID")
	fmt.Scanln(&id)

	// Print all KeyGen-related Parameters
	secKey := keyGen(id, mk, pubKey)
	fmt.Println("...Running KeyGen Algorithm")
	fmt.Println("...Secret Key for device ID generated \u2713")

	fmt.Println("\n")
	fmt.Println("-------  Encrypt  ---------")
	// l := len(id) // ID bit length
	fmt.Println("Please enter the list of covered IDs, e.g. **1***10*")
	fmt.Scanln(&cl)

	fmt.Println("Please enter the list of revoked IDs, e.g. *****110*")
	fmt.Scanln(&rl)

	s := &subset{cl: cl, rl: rl} // subset consisting of CL and RL

	// Print ID,CL,RL
	printID(id, s)

	// Create random message M in GT
	inputMessage := createRandomM(pubKey)
	fmt.Println("\n")
	fmt.Println("...Random Message generated \u2713")
	// fmt.Println("Input Message: ", inputMessage.ToString())

	// Call Encrypt
	cipher := encrypt(s, pubKey, inputMessage)
	fmt.Println("...Message Encrypted \u2713")

	// Decrypt Message
	fmt.Println("\n")
	fmt.Println("...Message sent \u2713")

	fmt.Println("\n")
	fmt.Println("-------  Decrypt  ---------")
	fmt.Println("...Trying to decrypt message for you")
	outputMessage, err := decrypt(s, id, secKey, cipher)
	if err != nil {
		fmt.Println("Error: ", err)
	} else {
		equalMes := inputMessage.Equals(outputMessage) // test if encrypted message is same as decrypted message
		if equalMes {
			fmt.Println("...Message successfully Decrypted on Device\u2713")
			fmt.Println("\n")
			// fmt.Println("Output Message:\n ", outputMessage.ToString())
		} else {
			fmt.Println("ERROR: The decrypted message is not correct, your ID is not part of the covered group")
		}
	}
}
