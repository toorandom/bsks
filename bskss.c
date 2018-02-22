/*
 * Beck shared key system server v0.0.1
 * default bind port is 7000/tcp
 * This version is for testing, the code is not clean and im not
 * freeing/cleaning some memory addresses
 * rduarte@ciencias.unam.mx
 *
 */
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <ctype.h>
#include <signal.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>

#define DEFAULT_PORT 7000
#define DEFAULT_GEN 5
#define DEFAULT_PRIME_BITS 128
#define DH_SYSTEM 1
#define INIT 0xaabbccdd
#define END 0x11223344
void
password (uint8_t * buf, uint16_t len)
{
  uint8_t alpha[] =
    "abcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%()1234567890";
  uint32_t i;
  for (i = 0; i < len; i++)
        printf ("%c", alpha[buf[i] % sizeof (alpha)]);
  printf ("\n");
  return;
}


int32_t
listen_tcp (uint16_t port, struct sockaddr_in cnx)
{

  int32_t localfd;
  if ((localfd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      perror ("socket");
      exit (-1);
    }

  cnx.sin_family = AF_INET;
  cnx.sin_port = htons (port);
  cnx.sin_addr.s_addr = INADDR_ANY;
  memset (&cnx.sin_zero, 0, 8);
  if ((bind (localfd, (struct sockaddr *) &cnx, sizeof (struct sockaddr))) <
      0)
    {
      fprintf (stderr, "Cannot bind to socket\n");
      perror ("bind");
      close (localfd);
      exit (-1);
    }
  if ((listen (localfd, 2)) < 0)
    {
      fprintf (stderr, "Cannot listen socket\n");
      perror ("listen");
      close (localfd);
      exit (-1);
    }
  return localfd;
}



void printh (unsigned char *buf, int size);
void
callback (int p, int n, void *arg)
{

  char c = '*';
  if (p == 0)
    c = '.';
  if (p == 1)
    c = '+';
  if (p == 2)
    c = '*';
  if (p == 3)
    c = '\n';
  BIO_write ((BIO *) arg, &c, 1);
  (void) BIO_flush ((BIO *) arg);
}

/* Values to receive after other party nows the generator and shared_key_size */

typedef struct remote_numbers_info_t
{
  uint32_t packet_init;
  uint8_t p_size;
  uint32_t packet_end;
} remote_numbers_info;

int
main (int argc, char **argv)
{

  DH *dh_system;
  BIGNUM *remote_pub;
  BIO *out = BIO_new (BIO_s_file ());
  int32_t t, rsock, lsock,sin_size = sizeof(struct sockaddr_in); 
  uint8_t *srpub, *spub, *sprime, *ss =
    (uint8_t *) calloc (DEFAULT_PRIME_BITS / 8, sizeof (uint8_t));
  struct sockaddr_in local_cnx, remote_cnx;
  lsock = listen_tcp (DEFAULT_PORT, local_cnx);
  rsock = accept (lsock, (struct sockaddr *) &remote_cnx, &sin_size);

  if (rsock < 0)
    {
      perror ("accept");
      close (lsock);
      exit (-1);
    }

  BIO_set_fp (out, stdout, BIO_NOCLOSE);
  fprintf (stderr, "Generating public key and shared prime\n");
  dh_system =
    DH_generate_parameters (DEFAULT_PRIME_BITS, DEFAULT_GEN, callback, out);
  fprintf (stderr, "Sending shared prime ");
  BN_print (out, dh_system->p);
  printf ("\n");
  sprime = (uint8_t *) calloc (DEFAULT_PRIME_BITS / 8, sizeof (int8_t));
  BN_bn2bin (dh_system->p, sprime);
  if (write (rsock, sprime, DEFAULT_PRIME_BITS / 8) !=
      (t = BN_num_bytes (dh_system->p)))
    {
      fprintf (stderr,
	       "Network error sending prime information .. sent %d bytes\n",
	       t);
      close (rsock);
      close (lsock);
      exit (-1);
    }

  fprintf (stderr, "Waiting for public key...\n");
  remote_pub = BN_new ();
  srpub = (uint8_t *) calloc (DEFAULT_PRIME_BITS / 8, sizeof (uint8_t));
  t = read (rsock, srpub, DEFAULT_PRIME_BITS / 8);
  BN_bin2bn (srpub, DEFAULT_PRIME_BITS / 8, remote_pub);
  if (t != DEFAULT_PRIME_BITS / 8)
    {
      fprintf (stderr, "Network error receiving public key %d bytes\n", t);
      close (rsock);
      close (lsock);
      exit (-1);
    }
  DH_generate_key (dh_system);
  fprintf (stderr, "Sending public key\n");
  spub = (uint8_t *) calloc (DEFAULT_PRIME_BITS / 8, sizeof (uint8_t));
  BN_bn2bin (dh_system->pub_key, spub);
  if (write (rsock, spub, DEFAULT_PRIME_BITS / 8) !=
      (t = BN_num_bytes (dh_system->pub_key)))
    {
      fprintf (stderr, "Network error sending public key .. sent %d bytes\n",
	       t);
      close (rsock);
      close (lsock);
      exit (-1);
    }
  fprintf (stderr, "Shutting down file descriptor\n");
  shutdown(rsock,SHUT_RDWR);
  close(rsock);
  shutdown(lsock,SHUT_RDWR);
  close (lsock);
  fprintf (stderr, "Calculating shared secret\n");
  DH_compute_key (ss, remote_pub, dh_system);
  printf ("remote pub:\n");
  BN_print (out, remote_pub);
  printf ("\ngen\n");
  BN_print (out, dh_system->g);
  printf ("\nprime\n");
  BN_print (out, dh_system->p);
  printf ("\nlocal pub\n");
  BN_print (out, dh_system->pub_key);
  printf ("\n");
  printh (ss, DEFAULT_PRIME_BITS / 8);
  printf("Shared secret: ");
  password (ss, DEFAULT_PRIME_BITS / 8);
  free (ss);
  free (spub);
  free (srpub);
  free (sprime);
  return 0;
}

void
printh (unsigned char *buf, int size)
{
  int i;
  for (i = 0; i < size; i++)
    {
      printf ("%02x:", buf[i]);
    }
  printf ("\n\n");
  return;
}
