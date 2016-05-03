/* Colt Darien Spring 2016
*  This code is written to be used with the Brain Controlled Smart Home senior design project
*  It provides a scalable server client model that will allow more devices to be connected to the smart home and more easily managed by use of raspberry pi controllers(or similar devices( in every room
* The devices communicate and are authenticated over secure communication using a hybrid cryptography setup. A different architecture would probably be much faster (like establishing a session key and using a symmetric key for all communication other than intial negotiation, and key exchange) A hybrid system will be much slower for short messages, but only slightly so for large messages. For this reason, and because I wanted to learn about a hybrid system instead, I chose to go with it.
 */
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/coltstrgj/CS-Research/connect"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
)

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                  Utility Functions                                             //
////////////////////////////////////////////////////////////////////////////////////////////////////
func check(name string, e error) {
	if e != nil {
		//fmt.Printf(".")
		fmt.Printf("%s: GAVE ERROR: %s\n", name, e)
	}
}

// This will take input and un-marshal it (from json) into a map
func unmarshalMessage(message []byte) map[string]string {
	// Maps are cool, take a look at them
	var dat map[string]string
	json.Unmarshal(message, &dat)
	return dat
}

//Format the message with json
func marshalMessage(messageType string, messageSender string, messageContents string) []byte {
	messageFormatted := &connect.Message{
		MessageType:     messageType,
		MessageSender:   messageSender,
		MessageContents: messageContents}
	//Now actually format it
	message, err := json.Marshal(messageFormatted)
	check(messageSender, err)
	// Check for errors
	return message
}

func readFile(fileName string) []byte {
	data, err := ioutil.ReadFile(fileName)
	check("Reading File"+fileName, err)
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		fmt.Println("ERROR: File Does not exist or is blank") // path/to/whatever does not exist
	}
	//  data = data[0:len(data)-1]//get rid of the EOF character
	return data
}

func writeFile(fileName string, data []byte) {
	file, err := os.Create(fileName)
	check("Opening File for writing"+fileName, err)
	defer file.Close() //this is going to close the file after we return (defer is cool)
	_, err = file.Write(data)
	check("Writing File"+fileName, err)
}

func readInput(send chan<- string) { // This is to read input from keyboard, we will remove it when this is fully working
	reader := bufio.NewReader(os.Stdin)
	//Get the input, This will change in the future (when done testing) TODO also get rid of newline if you feel like it
	for {
		fmt.Print("Enter text: ")
		input, _ := reader.ReadString('\n')
		input = input[:len(input)-1]
		send <- input
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                  Cryptography Functions                                        //
////////////////////////////////////////////////////////////////////////////////////////////////////
//getRSAKey will check if there is an existing key at "fileName" (Which should just be the client name, exp: server), if not one is created and written to that file. The key is returned.
func getRSAKeyFromFile(fileName string) *rsa.PrivateKey {
	var key *rsa.PrivateKey
	//priv, key1, key2, err := elliptic.GenerateKey(elliptic.P224(), rand.Reader)
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		key, err := rsa.GenerateKey(rand.Reader, 4092)
		check("Error ", err)
		marshaledRSAPrivateKey := x509.MarshalPKCS1PrivateKey(key)
		writeFile(fileName, marshaledRSAPrivateKey)
		//fmt.Println(x509.MarshalPKCS1PrivateKey(key))
	}
	key, _ = x509.ParsePKCS1PrivateKey(readFile(fileName))
	return key
}

//Takes a public key in text of the form: big int:modulo
func parsePublicKey(keyText string) *rsa.PublicKey {
	keyParts := strings.Split(keyText, ":")
	if len(keyParts) != 2 {
		//TODO Uh Oh!
	}
	//Temp variable for the big int (trying to directly assign to key.N resulted in nil pointer)
	var temp big.Int
	//create the key
	key := new(rsa.PublicKey)
	//Unmarshal the key from the text
	temp.UnmarshalText([]byte(keyParts[0]))
	//Assign the
	key.N = &temp
	key.E, _ = strconv.Atoi(keyParts[1])
	return key
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                        Server Functions                                        //
////////////////////////////////////////////////////////////////////////////////////////////////////
func clientConnection(connection *connect.Connection) {
	recvMsg := make(chan string)
	go connect.ReceiveMessages(connection, recvMsg)

	for {
		select {
		case msg := <-recvMsg:
			// Receive messages from server
			fmt.Println("|===================================================================|")
			fmt.Println(connection.Name + ": " + msg)
			//case input := <-recv:
			//	// got input from main server thread, forward to client TODO
			//	sendMessage("CONSOLE DEBUG INPUT", connection, []byte(input))
		}
	}
}

func startServer(url string) {
	// Channel to get information from clients wanting to connect back to main server thread
	recv := make(chan *connect.Connection)
	//TODO this is nothing, but I use it for debug
	timer1 := time.NewTicker(time.Second * 15).C

	// Start a new goroutine for handling incoming requests
	go connect.RequestHandler(url, recv)

	// Receive the replies from clients
	//recvMessage := make(chan string)
	//go receiveMessages(sock, recvMessage)

	// infinite loop to handle this stuff
	for {
		select {
		case connection := <-recv: // Got a message from a client that needs to be handled here

			go clientConnection(connection)
			//message := unmarshalMessage([]byte(msg))
			//if message["MessageType"] == "JOIN_REQUEST" {
			//	fmt.Println("Request from the clients")
			//}
		case <-timer1:
			fmt.Println("Timer went off")
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                        Client Functions                                        //
////////////////////////////////////////////////////////////////////////////////////////////////////

//clientRun is an internal method, users should implement this method on their own, so that it can have the desired functionality. This one is just for debugging and testing
func clientRun(client *connect.Connection) {
	// Close this socket even if program crashes, or when we retrun from this method (never)
	defer client.Socket.Close()

	recvMsg := make(chan string)
	go connect.ReceiveMessages(client, recvMsg)

	// Read inpput from console,TODO this will be gone some time soon, it is just for debugging
	recvInput := make(chan string)
	go readInput(recvInput)

	for {
		select {
		case msg := <-recvMsg:
			// Receive messages from server
			fmt.Println(msg)
		case input := <-recvInput:
			// got input from console, send it to server
			connect.SendMessage("Debug input from console", client, []byte(input))
		}
	}
}

func startClient(url string, name string) {
	client := &connect.Connection{
		Name: name,
		URL:  url}
	client.RSAPrivateKey = getRSAKeyFromFile(client.Name + ".key")
	//fmt.Println(client.RSAPrivateKey.PublicKey)
	connect.ConnectClient(client)
	clientRun(client)
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                        Main                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////

func main() {
	if len(os.Args) > 2 && os.Args[1] == "server" {
		startServer(os.Args[2])
		os.Exit(0)
	}
	if len(os.Args) > 3 && os.Args[1] == "client" {
		startClient(os.Args[2], os.Args[3])
		os.Exit(0)
	}
	//TODO fix this message when finished
	fmt.Println("Usage: survey server|client <PORT>\n",
		"URL for server should just be a port numbr",
		"URL for client should be of the form XXX.XXX.XXX.XXX:PORT, for example'127.0.0.1:40401' ")
	os.Exit(1)
}
