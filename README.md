# CS-Research
This is a public repository with the history stripped from a CSU project called Brain Controlled Smart Home. The revision history contained code that is not allowed to be open sourced at this point.
#Connect
connect (also called cognitive connect when it is used by the BCSH team) is a program written in order to be used with the Brain Controlled Smart Home senior design project at CSU. 
This code is intended to carry commands securely and quickly from the brain control server to "nodes" that are in each room. These nodes are made up of cheap computers like the raspberry pi. The nodes then distribute these commands to the smart devices. 
This code is just like any other go code, but if it is in a private repository on github, you will need to manually add it to $GOPATH/src/github.com/...., in this case: 

`cd $GOPATH/src/github.com/csubcsh/cognitive-connect`

`git clone https://github.com/csubcsh/cognitive-connect.git`

Or in the case of this repository (with no revision history before this point)

`go get github.com/coltstrgj/CS-Research`
##Usage
The connect/connect.go code is a library. An example program using this is in examples/simple.go. It has both a client and server in the file
The server simply prints all of the incoming messages. The client example takes input from console and sends them to the server. 
###Client
to run the client simply run the following command:
`go run simple.go client 127.0.0.1:40401 clientName`
Feel free to change clientName to anything that you can use to identify the client, and change 127.0.0.1:40401 to any ip and port that you like (if you run both the client and server on the same machine, ip needs to be 127.0.0.1
###Server
to run the server example:
`go run simple.go server 40401`

##Cryptography
The program uses 256 bit AES keys, and 4096 bit RSA keys for communication. The server will automatically generate it's own keys if one does not already exist. 
This connect.go library handles several things for the user. The handshakes to initialize connections is encrypted using Public key cryptography. After the handshake, all messages exchanged are send using a hybrid cryptography. A one time use AES key is used to encrypt the messages, and this key is then encrypted with the recipients public key. The messages are also signed with the senders private key. This guarentees the messages integrity, and confidentiality, as well as not being faster than vanilla public key cryptography for long messages. 
In the future, it would be ideal to identify whether clients are permitted to connect based on their public key in a trusted list, and if not, user input. At this point in time, neither is implemented. 
