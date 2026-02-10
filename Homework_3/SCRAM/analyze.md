# SCRAM protocol 
(Salted Challenge Response Authentication Mechanism)

To prevent a man in the middle attacker or an attacker who has access to the database from reading the hashed password, a "salt" is added.
This salt is a random string of bytes that is added to the password before hashing. 
That way the attacker can't perform offline attacks to find the password.

## client authentication in SCRAM
To provide client authentication, the client samples a challenge $ch1$ and sends it to the server.
The server responds by sending a random salt $r$, a nonce $n$ and the challenge $ch2$.
Then the client can calculate the salted password $spw = H^n(r, pw)$,
the client key $c = HMAC(spw, "Client Key")$and the authentication message $auth_msg = [Client Name] || r, n, ch1, ch2$.
Combining them gives the client signature $sig = HMAC(H(c), auth_msg)$ and the client proof $proof = c \oplus sig$.
This proof is sent to the server.

In short, the client proof consists of the client key and the signature wich again consists of the salted password and data known by the server.


![SCRAM_protocol_client-proof](Homework_3/SCRAM/SCRAM_protocol_client-proof.png)


## server authentication in SCRAM
To provide server authentication, the client samples a challenge $ch1$ and sends it to the server.
The server calculates the server key $s = HMAC(spw, "Server Key")$, already knowing the salted password $spw = H^n(r,pw)$ and the authentication message $auth_msg = [Client Name] || ch1$.
Combining them gives the server signature $sig = HMAC(s, auth_msg)$.
This signature is sent to the client.

In short, the server signature consists of the salted password and data known by the client.

![SCRAM_protocol_server-proof](Homework_3/SCRAM/SCRAM_protocol_server-proof.png)

## SCRAM without TLS
TLS provides a shared secret between the client and the server, which is then used to encrypt the communication.
Without TLS, a man in the middle attacker can read the unencrypted communication.
That way the attacker can simply read the salt and use it in offline attacks (hashing the salt with the dictionary password). 

![SCRAM_protocol](Homework_3/SCRAM/SCRAM_protocol.png)
