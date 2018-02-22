/*
 * Beck Shared Key system client v0.0.1
 * Default port to connect is 7000
 * no option avalaible for now ... just argv[1] must be the ip
 * address
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

int
main (int argc, char **argv)
{

  struct sockaddr_in cnx;
  int32_t sock, t;
  uint8_t *ss = (uint8_t *) calloc (DEFAULT_PRIME_BITS / 8, sizeof (uint8_t));
  BIGNUM *prime, *remote_pub;
  uint8_t *sprime, *sremote_pub, *spub;
  BIO *out = BIO_new (BIO_s_file ());
  DH *dh_sys = DH_new ();
  if(argc < 2) {
        fprintf(stderr,"Need to provide an IP where a bsks service is running\nrduarte@ciencias.unam.mx\n");
        return 0;
  }
  cnx.sin_family = AF_INET;
  cnx.sin_port = htons (DEFAULT_PORT);
  cnx.sin_addr.s_addr = inet_addr (argv[1]);
  sock = socket (AF_INET, SOCK_STREAM, 0);
  fprintf (stderr, "Connecting..\n");
  connect (sock, (struct sockaddr *) &cnx, sizeof (struct sockaddr_in));
  BIO_set_fp (out, stdout, BIO_NOCLOSE);
  fprintf (stderr, "Reading remote shared prime information\n");
  prime = BN_new ();
  sprime = (uint8_t *) calloc (DEFAULT_PRIME_BITS / 8, sizeof (uint8_t));
  t = read (sock, sprime, DEFAULT_PRIME_BITS / 8);
  BN_bin2bn (sprime, DEFAULT_PRIME_BITS / 8, prime);

  printf ("Received prime ");
  BN_print (out, prime);
  printf ("\n");
  if (t != DEFAULT_PRIME_BITS / 8)
    {
      fprintf (stderr, "Network error receiving prime information\n");
      close (sock);
      exit (-1);
    }
  fprintf (stderr, "Setting DH parameters with prime received\n");
  dh_sys->p = BN_dup (prime);

  dh_sys =
    DH_generate_parameters (DEFAULT_PRIME_BITS, DEFAULT_GEN, callback, out);
  dh_sys->p = BN_dup (prime);
  DH_generate_key (dh_sys);
  fprintf (stderr, "Sending public key\n");
  spub =
    (uint8_t *) calloc (BN_num_bytes (dh_sys->pub_key), sizeof (uint8_t));
  t = BN_bn2bin (dh_sys->pub_key, spub);
  t = write (sock, spub, DEFAULT_PRIME_BITS / 8);
  free (spub);
  if (t != DEFAULT_PRIME_BITS / 8)
    {
      fprintf (stderr, "Error sending public key.. bytes = %d, sock = %d\n",
	       t, sock);
      perror ("send");

      close (sock);
      exit (-1);
    }

  fprintf (stderr, "Receiving remote public key\n");
  remote_pub = BN_new ();
  sremote_pub = (uint8_t *) calloc (DEFAULT_PRIME_BITS / 8, sizeof (uint8_t));
  t = read (sock, sremote_pub, DEFAULT_PRIME_BITS / 8);
  BN_bin2bn (sremote_pub, DEFAULT_PRIME_BITS / 8, remote_pub);

  if (t != DEFAULT_PRIME_BITS / 8)
    {
      fprintf (stderr, "Network error receiving public key information\n");
      close (sock);
      exit (-1);
    }

  fprintf (stderr, "Closing connection..\n");
  shutdown(sock,SHUT_RDWR);
  close(sock);
  fprintf (stderr, "Calculating shared secret..\n");
  DH_compute_key (ss, remote_pub, dh_sys);
  printf ("local pub key\n");
  BN_print (out, dh_sys->pub_key);
  printf ("\nprime\n");
  BN_print (out, dh_sys->p);
  printf ("\nremote pub\n");
  BN_print (out, remote_pub);
  printf ("\ng\n");
  BN_print (out, dh_sys->g);
  printf ("\n");
  printh (ss, DEFAULT_PRIME_BITS / 8);
  printf("Shared secret: ");
  password (ss, DEFAULT_PRIME_BITS / 8);
  free (ss);
  free (sprime);
  free (sremote_pub);
  return 0;
}
