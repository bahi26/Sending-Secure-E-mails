#Sending Secure E-mails

Project Objectives:
1. Apply security concepts you study in the course to a real world problem.
2. Enhance student’s understanding of encryption algorithms.
3. Have experience with code breaking.
Project Requirement:
Nowadays, sending secure e-mails has a primary concern due to the extensive usage of e-mails, so they
must be sent in a secure way. Sending e-mails requires achieving both confidentiality and authentication
since you do not want your inbox messages to be read by other people (confidentiality), and you want to
verify the sender’s e-mail address for any e-mail you got (authentication).
There are currently two actively proposed methods for providing these security services
Secure/Multipurpose Internet Mail Extension (S/MIME) and Pretty Good Privacy (PGP).
You are required to develop an application that sends and receives secure encrypted e-mails using PGP
protocol.
The Detailed Steps of the protocol are as follows:
Suppose Alice wants to send a secure e-mail to Bob, she should do the following steps:
1. Generate a random session key Ks and encrypt it using Bob’s public key using RSA
algorithm.
2. Encrypt the plain text e-mail using DES with the session key Ks generated in step 2, (As you
know DES key=56 bits).
3. Send both the encrypted session key generated in step (2) Ks along with the encrypted e-mail
generated in step 3.
On the receiver side, Bob should do the following steps upon receiving an-email from Alice:
1. Decrypt the received session key Ks, using Bob’s private key.
2. Use the retrieved session key to decrypt the received e-mail.