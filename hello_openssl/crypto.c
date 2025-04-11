#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

// https://opensource.com/article/19/6/cryptography-basics-openssl-part-1
// https://quuxplusone.github.io/blog/2020/01/24/openssl-part-1/
// https://developer.ibm.com/tutorials/l-openssl/
// https://github.com/theno/openssl-examples/blob/master/links.md
// https://www.codeproject.com/Articles/5388092/Building-Secure-Applications-with-OpenSSL
// https://github.com/openssl/openssl/wiki/Simple_TLS_Server

// sudo apt install libssl-dev
// gcc -o crypto crypto.c -lssl -lcrypto

int main() { 
	/* Step 1: Initialize SSL */
	SSL_library_init();
	SSL_load_error_strings();

	/* Step 2: Create the SSL context */
	SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {    
		perror("Error creating SSL_CTX");
		ERR_print_errors_fp(stderr);
		exit(-1);        
	}

	/* Step 3: Create BIO structure */
	BIO* bio = BIO_new_ssl_connect(ctx);
	if (!bio) {
		perror("Error creating BIO");
		ERR_print_errors_fp(stderr);
		exit(-1);
	}

	/* Step 4: Set the SSL mode */
	SSL* ssl = NULL;
	BIO_get_ssl(bio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	/* Step 5: Attempt connection */
	BIO_set_conn_hostname(bio, "www.google.com:443");
	if (BIO_do_connect(bio) <= 0) {
		perror("Error connecting to server"); 
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		BIO_free_all(bio);
		exit(-1);
	}

	/* Step 6: Submit GET request */
	BIO_puts(bio, "GET / HTTP/1.1\r\nHost: www.google.com \r\nConnection: close\r\n\r\n");

	/* Step 7: Print response when available */
	char response[1024];    
	while(1) {
	memset(response, '\0', 1024);
	if (BIO_read(bio, response, 1024) <= 0)
		break;
		puts(response);
	}

	/* Step 8: Deallocate resources */
	SSL_CTX_free(ctx);
	BIO_free_all(bio);
    
	printf("\nEnd\n");

	return 0; 
}