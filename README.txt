BSKS (Beck Shared Key System)

This is just a small thing using libcrypto to solve a problem i have with a friend
he does not have PGP , and he is not planning to use it.. so i need to send encrypted
information to him , but we have a problem... we need to send keys via the same insecure
network ... so we need to agree with a password.. so this simple beta protocol 
generates a random public key per session and negotiate the shared secret in both sides
using diffie hellman (for now)

USAGE:

Compiling:

gcc -lcrypto -O3 -funroll-loops -Wall -pedantic -ansi -fomit-frame-pointer -s bskss.c -o bskss
gcc -lcrypto -O3 -funroll-loops -Wall -pedantic -ansi -fomit-frame-pointer -s bsksc.c -o bsksc

in solaris x86 or sparc 32/64 just add -lnsl -lsocket , and if your libcrypto.so is 64 bit
add -m64


Default settings are in macros...

the shared key len is 128 bits by default (16 bytes)
and the generator is 7 , the default port is 7000/tcp

this settings must be the same in but sides.. in future a configuration

file for the server may be used and this information must be transmited to the

client before the actual negotiation.



RUNNING:


In server with IP 1.2.3.4 :


./bskss


In client

./bsksc 1.2.3.4


And you will get the shared secret..

Im gonna implement some digital signatures and other things to make it multisession

and a standard daemon..


rduarte@ciencias.unam.mx

Eduardo Ruiz Duarte
