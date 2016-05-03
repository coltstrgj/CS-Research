/* Colt Darien Spring 2016
*  This code is written to be used with the Brain Controlled Smart Home senior design project
*  It provides a scalable server client model that will allow more devices to be connected to the smart home and more easily managed by use of raspberry pi controllers(or similar devices( in every room
* The devices communicate and are authenticated over secure communication using a hybrid cryptography setup. A different architecture would probably be much faster (like establishing a session key and using a symmetric key for all communication other than intial negotiation, and key exchange) A hybrid system will be much slower for short messages, but only slightly so for large messages. For this reason, and because I wanted to learn about a hybrid system instead, I chose to go with it.
 */
package connect

import (
	"bufio"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-mangos/mangos"
	"github.com/go-mangos/mangos/protocol/pair"
	"github.com/go-mangos/mangos/transport/ipc"
	"github.com/go-mangos/mangos/transport/tcp"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                  Structs                                                       //
////////////////////////////////////////////////////////////////////////////////////////////////////

//Struct for messages
type Message struct {
	MessageType     string //Should be either command, response, or request so that the server/client knows how to continue
	MessageSender   string //This will be the name of the client that is sending
	MessageContents string
}

type secureMessage struct {
	Key             []byte //contains the random key that was generated in order to encrypt the message, key itself is encrypted with public key of recipient
	Signature       []byte //The signature of the message, so that we can ensure security of the message. Signed with senders private key.
	MessageContents []byte //The encrypted message
}

//Connection stores all of the data that is required for a connection, It holds information like its own name, Its private key(in go's library for rsa, private key types contain the corresponding public key), the partners public key
type Connection struct {
	Name             string          //The name of the current device (eg: server, living_room, etc)
	URL              string          //The URL that it connects to (eg: 127.0.0.1:40401)
	Socket           mangos.Socket   //The socket that it uses for communication
	RSAPrivateKey    *rsa.PrivateKey //This devices private key (contains public key)
	PartnerPublicKey *rsa.PublicKey  //The connection partners public key
}

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
	messageFormatted := &Message{
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

//marshalSecureMessage, like marshalMessage is not necessary, it just made the code look cleaner, and I could read it easier.
func marshalSecureMessage(key []byte, signature []byte, messageContents []byte) []byte {
	messageFormatted := &secureMessage{
		Key:             key,
		Signature:       signature,
		MessageContents: messageContents}
	//Now actually format it
	message, err := json.Marshal(messageFormatted)
	check("Marshal encrypted message", err)
	return message
}

func decodeBase64(value string) []byte {
	decoded, _ := base64.StdEncoding.DecodeString(value)
	return decoded
}

func ReceiveMessages(connection *Connection, send chan<- string) {
	// The errors will be in this variable to be checked later
	var err error
	// The array that the emssage will be read into
	var msg []byte
	for { // Infinite loop of receiving messgaes
		// receive the message
		msg, err = connection.Socket.Recv()
		check(connection.Name, err)

		//unmarshal message
		messageEncrypted := unmarshalMessage(msg)

		//decrypt the symetric key, and check if it is valid
		encryptedKey := decodeBase64(messageEncrypted["Key"])
		signature := decodeBase64(messageEncrypted["Signature"])
		key, valid := decryptAndCheckSignature(connection.RSAPrivateKey, connection.PartnerPublicKey, encryptedKey, signature)
		if valid == false {
			continue //skip the rest of the loop and wait for a new message
		}

		//change message from base64 back to bytes (thanks json...)
		messageContents := decodeBase64(messageEncrypted["MessageContents"])
		//Un-encrypt the message
		message := cfbDecrypter(key, messageContents)
		//Send the results back to the parent go routine
		send <- string(message)
	}
}

func SendMessage(msgType string, connection *Connection, message []byte) {
	key := generateAESKey()
	//Format the message
	messageFormatted := marshalMessage(msgType, connection.Name, string(message))
	messageEncrypted := cfbEncrypter(key, messageFormatted)
	encryptedKey, signature := encryptAndSign(connection.PartnerPublicKey, connection.RSAPrivateKey, key)
	//format the message
	sendableMessage := marshalSecureMessage(encryptedKey, signature, messageEncrypted)
	//Send the message
	// The errors will be in this variable to be checked later
	err := connection.Socket.Send(sendableMessage)
	// Check this error by hand so that we know specifically what the problem is
	check(connection.Name, err)
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

//decryptAndCheckSignature will do what the title says. It is to clean the code below.
func decryptAndCheckSignature(privKey *rsa.PrivateKey, pubKey *rsa.PublicKey, cipherText []byte, signature []byte) ([]byte, bool) {
	//Decrypt the message
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, cipherText)
	check("Decrypting Message", err)
	//verify the signature
	if !verifySignature(pubKey, plainText, signature) {
		return nil, false
	}
	//return the decrypted message and boolean for if signature passed (message is false if sig fails)
	return plainText, true
}

func getInitMessage(connection *Connection, sock net.Conn) []byte {
	// The errors will be in this variable to be checked later
	var err error
	// receive the message
	// Read the incoming until we get a 0xFF (which is what I chose for my terminating character. This can be easily changed, it was just for debugging purposes
	recvMessage, err := bufio.NewReader(sock).ReadString(byte(0xFF))
	check("Handshake receive", err)
	// Remove the final byte from message (because messages are terminated with a byte that is not actual text)
	recvMessage = recvMessage[:len(recvMessage)-1]

	//unmarshal message
	messageEncrypted := unmarshalMessage([]byte(recvMessage))
	//fmt.Println("Message: Received************************************************************************")
	//fmt.Println(messageEncrypted)
	//fmt.Println("************************************************************************")

	//decrypt the symetric key, and check if it is valid
	encryptedMessage := decodeBase64(messageEncrypted["MessageContents"])
	signature := decodeBase64(messageEncrypted["Signature"])
	message, valid := decryptAndCheckSignature(connection.RSAPrivateKey, connection.PartnerPublicKey, encryptedMessage, signature)
	if valid == false {
		return nil //message has been tampered with
	}

	//change message from base64 back to bytes (thanks json...)
	//messageContents := decodeBase64(messageEncrypted["MessageContents"])
	//Un-encrypt the message
	//message := cfbDecrypter(key, messageContents)
	//Send the results back to the parent go routine
	return message
}

//encryptAndSign will do what the title says. It is to clean the code below.
func encryptAndSign(encryptKey *rsa.PublicKey, sigKey *rsa.PrivateKey, plainText []byte) ([]byte, []byte) {
	//Sign the message
	signature := signMessage(sigKey, plainText)

	//Encrypt the message
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, encryptKey, plainText)
	check("Encrypting Message", err)
	//fmt.Println("CipherText: ************************************************************************")
	//fmt.Println(string(cipherText))
	//fmt.Println("************************************************************************")
	//return them both
	return cipherText, signature
}

func sendInitMessage(connection *Connection, sock net.Conn, message []byte) {

	encryptedMessage, signature := encryptAndSign(connection.PartnerPublicKey, connection.RSAPrivateKey, message)
	//format the message
	connectionInfoMsg := marshalSecureMessage([]byte("Handshake messages public key based"), signature, encryptedMessage)
	// Add terminating character
	connectionInfoMsg = append(connectionInfoMsg, 0xFF)
	// Send the message to the client
	sock.Write(connectionInfoMsg)
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

func generateAESKey() []byte {
	//Generate a new random key (32 bytes long is 256 bits)
	key := make([]byte, 32)
	_, err := rand.Read(key)
	check("Generating key", err)
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

func cfbDecrypter(key []byte, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	// Cipher text does not need to be a multiple of block size, but must be greater than blocksize.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
	//fmt.Printf("%s", ciphertext)
	// Output: some plaintext
	return ciphertext
}

func cfbEncrypter(key []byte, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	return ciphertext
}

func signMessage(key *rsa.PrivateKey, message []byte) []byte {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	PSSmessage := message
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, key, newhash, hashed, &opts)
	check("Signing", err)
	return signature
}

func verifySignature(key *rsa.PublicKey, message []byte, signature []byte) bool {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	PSSmessage := message
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	err := rsa.VerifyPSS(key, newhash, hashed, signature, &opts)
	if err != nil {
		return false
	}
	return true
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                        Server Functions                                        //
////////////////////////////////////////////////////////////////////////////////////////////////////
func generateSocket(server *Connection, conn net.Conn) mangos.Socket {
	// Try opening on ports over and over until it works
	// Starting at a port
	var clientPort int = 31337
	var clientSock mangos.Socket
	// Create mangos sockets until we get one running, then send info to client
	clientSock, err := pair.NewSocket()
	check("Opening socket", err)
	//TODO what do I do in this case? this is a problem that should never happen. Just try new port? kill program?
	clientSock.AddTransport(ipc.NewTransport())
	clientSock.AddTransport(tcp.NewTransport())

	for {
		if clientPort >= 65535 {
			//TODO we have a problem
			clientPort = 1024
		}
		//Try opening the port
		//TODO TODO TODO this is linux dependant I think. Need to fix this really bad
		if err = clientSock.Dial("tcp://127.0.0.1:" + strconv.Itoa(clientPort)); err != nil {
			// This was unopenable, so try a new port number
			//TODO how to choose a new port?
			fmt.Printf("Unable to open port: %d\n", clientPort)
			//clientSock.Close()
			clientPort += 15
			// If error, try again on new port, if not finish things up
		} else {
			// We are ready to send this info to the client
			// Format the socket that we started so that
			connectionInfoMsg := marshalMessage("CONNECTION INFORMATION", "Server", strconv.Itoa(clientPort))

			// Add terminating character
			//connectionInfoMsg = append(connectionInfoMsg, 0xFF)
			// Send the message to the client
			//conn.Write(connectionInfoMsg)
			sendInitMessage(server, conn, connectionInfoMsg)

			// Wait for reply from client confirming that this worked for them as well
			// Read the incoming until we get a 0xFF (which is what I chose for my terminating character. This can be easily changed, it was just for debugging purposes
			//recvMessage, _ := bufio.NewReader(conn).ReadString(byte(0xFF))
			// Remove the final byte from message (because messages are terminated with a byte that is not actual text)
			//recvMessage = recvMessage[:len(recvMessage)-1]
			recvMessage := getInitMessage(server, conn)
			// The message is Json formatted, we want to return it as a map
			message := unmarshalMessage([]byte(recvMessage))
			if message["MessageType"] == "ACKNOWLEDGE" { //TODO in future also check contents for public key
				fmt.Println("Request from the client was succesfully fulfilled")
			} else { // The port on client machine is already in use
				fmt.Printf("Client (%s) could not access port: %d\n\tTrying again\n", "Server", clientPort)
				//clientSock.Close()
				clientPort += 1
				// Skip the rest of this loop and try again
				continue
			}
			// Exit the loop because we are done here
			break
		}
	}
	return clientSock
}

// Runs every time a client tries to connect
func connectionRequestHandler(conn net.Conn, server *Connection, chSend chan<- *Connection) {
	defer conn.Close() //close the connection upon leaving this
	var err error

	// Read the incoming until we get a 0xFF (which is what I chose for my terminating character. This can be easily changed, it was just for debugging purposes
	recvMessage, err := bufio.NewReader(conn).ReadString(byte(0xFF))
	check("UNIDENTIFIED NEW CLIENT", err)
	// Remove the final byte from message (because messages are terminated with a byte that is not actual text)
	recvMessage = recvMessage[:len(recvMessage)-1]
	// The message is Json formatted, we want to return it as a map
	message := unmarshalMessage([]byte(recvMessage))
	// Alert the terminal of the new connection
	fmt.Println("|-------------------------------------------------------------------|")
	fmt.Println("|New client connected with the following public key:                |")
	fmt.Println("|-------------------------------------------------------------------|")

	if message["MessageType"] == "JOINREQUEST" { //TODO in future also check contents for public key
		//Print the client information in console
		fmt.Printf("Request from the clients from: %s\n\tKey is %s\n", message["MessageSender"], message["MessageContents"])
		//Add the public key to server struct
		server.PartnerPublicKey = parsePublicKey(message["MessageContents"])
	} else { //TODO Should never happen unless shady business or mistaken message to server
		fmt.Println("SHADY BUSINESS!!")
		return
	}

	//TODO get user permission on either server or existing client to allow connection
	fmt.Println("|-------------------------------------------------------------------|")
	fmt.Println("|Automatically accepting all connections durring testing/debug phase|")
	fmt.Println("|-------------------------------------------------------------------|")

	//Reply with servers public key and ACK the connection request
	pubKey, _ := server.RSAPrivateKey.PublicKey.N.MarshalText()
	msg := marshalMessage("ACKNOWLEDGE", "Server", string(pubKey)+":"+strconv.Itoa(server.RSAPrivateKey.PublicKey.E))
	//fmt.Println(client.RSAPrivateKey.PublicKey)
	msg = append(msg, byte(0xFF))
	_, err = conn.Write([]byte(msg))

	clientSock := generateSocket(server, conn)
	// Set the recv to blocking operation
	clientSock.SetOption(mangos.OptionRecvDeadline, time.Second*0)
	server.Socket = clientSock
	// We are done here, move this thread over to the client connection
	chSend <- server
	//clientConnection(name, clientSock, recv, send)
}

// RequestHandler takes care of client connection requests. It allows for multiple devices to request connections at the same time without blocking. ChSend is the channel used to send Connection structs when a client joins the network. From the perspective of whoever calls RequestHandler, they will receive on the channel.
//TODO what do I name this thing?
// chSend and chRecv is only used for communication to main thread
// chClientSend and chClientRecv are channels to communicate to the socket (which in turn sends to the actual client)
func RequestHandler(port string, chSend chan<- *Connection) {
	server := &Connection{
		Name: "Server"}
	server.RSAPrivateKey = getRSAKeyFromFile("Server.key")
	// Close the connection when we return from this
	// This will create and setup the TCP socket to listen for all connections
	reqServer, _ := net.Listen("tcp", ":"+port)
	// Close the server later (whenever main closes including in a panic)
	defer reqServer.Close()
	for {
		newServer := &Connection{}
		*newServer = *server
		// Accept any incoming connection
		conn, _ := reqServer.Accept()
		go connectionRequestHandler(conn, newServer, chSend)
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                        Client Functions                                        //
////////////////////////////////////////////////////////////////////////////////////////////////////

//ConnectClient will connect the client to the server. The incoming Connection struct must have a valid URL and NAME. The Socket, clients private key, and servers public key will be added to the Connection. TODO this method returns false if anything fails.
/* OUTLINE OF EVENTS THAT SHOULD HAPPEN
1: NODE: sends request to server that incudes its public key
2: SERVER: gets permission to allow this client to connect (check if it already has this client as allowd to connect from previous connection)
3: SERVER: Generate a "pair" on arbitrary port and send this info to client
4: NODE: Ack the port (try to set it up and be sure it works)
4.5: if this port does not work, server needs to handle this, and try again until one works
*/
func ConnectClient(client *Connection) bool {
	serverConn, err := net.Dial("tcp", client.URL)
	var clientSock mangos.Socket
	// Check this error by hand
	if err != nil {
		fmt.Println("Server refused connection request.\n are input arguments correct? (run with --help)\n otherwise it could be on a different port, not running, or there are network problems")
		os.Exit(1)
	}
	fmt.Println("Contacting Server, Requesting to join")
	//Get ready to send server my public key
	pubKey, _ := client.RSAPrivateKey.PublicKey.N.MarshalText()
	msg := marshalMessage("JOINREQUEST", client.Name, string(pubKey)+":"+strconv.Itoa(client.RSAPrivateKey.PublicKey.E))
	msg = append(msg, byte(0xFF))
	//Send the join request
	//sendInitMessage(client, serverConn, msg)
	_, err = serverConn.Write([]byte(msg))

	//Get the reply (that contains the servers public key)
	reply, _ := bufio.NewReader(serverConn).ReadString(byte(0xFF))
	reply = reply[:len(reply)-1]
	//reply := getInitMessage(client, serverConn)
	//fmt.Println(reply)
	message := unmarshalMessage([]byte(reply))
	if message["MessageType"] == "ACKNOWLEDGE" {
		client.PartnerPublicKey = parsePublicKey(message["MessageContents"])
	} else {
		//We have a problem. The server probably turned us down when connecting or message was malformed
		return false
	}

	// Loop until we get one that works for us and server
	for {
		//reply, _ := bufio.NewReader(serverConn).ReadString(byte(0xFF))
		//reply = reply[:len(reply)-1]
		reply := getInitMessage(client, serverConn)

		//fmt.Println(reply)
		message := unmarshalMessage([]byte(reply))

		clientSock, err = pair.NewSocket()
		check(client.Name, err)
		//TODO what do I do in this case? this is a problem that should never happen. Just try new port? kill program?
		clientSock.AddTransport(ipc.NewTransport())
		clientSock.AddTransport(tcp.NewTransport())

		fmt.Printf("Trying to connect to server on port %s\n", message["MessageContents"])
		//Try opening the port
		//TODO TODO TODO this is linux dependant I think. Need to fix this really bad
		if err = clientSock.Listen("tcp://127.0.0.1:" + message["MessageContents"]); err != nil {
			// This port did not work for us, so ask for a new one
			msg = marshalMessage("FAIL", client.Name, "unable to open this port")

			//msg = append(msg, byte(0xFF))
			//_, err = serverConn.Write([]byte(msg))
			sendInitMessage(client, serverConn, msg)
		} else {
			fmt.Printf("Connected to server on port %s\n", message["MessageContents"])
			msg = marshalMessage("ACKNOWLEDGE", client.Name, "the port is open and functioning properly: "+message["MessageContents"])
			//msg = append(msg, byte(0xFF))
			//_, err = serverConn.Write([]byte(msg))
			sendInitMessage(client, serverConn, msg)
			break
		}
	}
	// Setting the options for the socket
	clientSock.SetOption(mangos.OptionRecvDeadline, time.Second*0)
	client.Socket = clientSock
	return true
}
