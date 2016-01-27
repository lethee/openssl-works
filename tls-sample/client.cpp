/*
 * TLS Client Sample
 *
 * see: https://wiki.openssl.org/index.php/SSL/TLS_Client
 *      https://www.openssl.org/docs/manmaster/ssl/ssl.html
 *      https://www.openssl.org/docs/manmaster/crypto/bio.html
 */
#include <iostream>

#include <openssl/err.h>
#include <openssl/ssl.h>

using namespace std;

class Client {
	unsigned long ssl_err = 0;
	SSL_CTX* ctx = nullptr;

public:
	void init() {
		ctx = SSL_CTX_new(TLSv1_method());
		ssl_err = ERR_get_error();
		if(!(ctx != nullptr)) {
			cerr << ssl_err << " [Error] SSL_CTX_new" << endl;
			return; /* failed */
		}
	}

	void connect(const char *host, const char * port) {
		BIO *web = nullptr;
		long res = 1;
		SSL *ssl = nullptr;
		BIO *out = nullptr;
		char hostname[128];

		cout << "BIO_new_ssl_connect" << endl;
		web = BIO_new_ssl_connect(ctx);
		ssl_err = ERR_get_error();
		if(!(web != nullptr))
		{
			cerr << ssl_err << " [Error] BIO_new_ssl_connect" << endl;
			return; /* failed */
		}

		cout << "BIO_set_conn_hostname" << endl;
		snprintf(hostname, sizeof(hostname), "%s:%s", host, port);
		res = BIO_set_conn_hostname(web, hostname);
		ssl_err = ERR_get_error();
		if(!(1 == res))
		{
			cerr << ssl_err << " [Error] BIO_set_conn_hostname" << endl;
			return; /* failed */
		}

		cout << "BIO_get_ssl" << endl;
		BIO_get_ssl(web, &ssl);
		ssl_err = ERR_get_error();
		if(!(ssl != nullptr))
		{
			cerr << ssl_err << " [Error] BIO_get_ssl" << endl;
			return; /* failed */
		}

		cout << "SSL_set_tlsext_host_name" << endl;
		res = SSL_set_tlsext_host_name(ssl, host);
		ssl_err = ERR_get_error();
		if(!(1 == res))
		{
			cerr << ssl_err << " [Error] ERR_get_error" << endl;
			return; /* failed */
		}

		out = BIO_new_fp(stdout, BIO_NOCLOSE);
		ssl_err = ERR_get_error();
		if(!(out != nullptr))
		{
			cerr << ssl_err << " [Error] BIO_new_fp" << endl;
			return; /* failed */
		}

		cout << "BIO_do_connect" << endl;
		res = BIO_do_connect(web);
		ssl_err = ERR_get_error();
		if(!(1 == res))
		{
			cerr << ssl_err << " [Error] BIO_do_connect" << endl;
			return; /* failed */
		}

		cout << "BIO_do_handshake" << endl;
		res = BIO_do_handshake(web);
		ssl_err = ERR_get_error();
		if(!(1 == res))
		{
			cerr << ssl_err << " [Error] BIO_do_handshake" << endl;
			return; /* failed */
		}

		const SSL_SESSION *session = SSL_get_session(ssl);
		if (session != nullptr) {
			SSL_SESSION_print(out, session);
		}

		// Certificate Verification Here

		X509* cert = SSL_get_peer_certificate(ssl);
		if(cert) {
			X509_print(out, cert);
			X509_free(cert);
		}

		// SSL_get_verify_result(ssl);

		// Contents

		BIO_puts(web, "GET " "/" " HTTP/1.1\r\nHost: ");
		BIO_puts(web, hostname);
		BIO_puts(web, "\r\nConnection: close\r\n\r\n");
		BIO_puts(out, "\nFetching: " "/" "\n\n");

		int len = 0;
		do {
			char buff[1536] = {};
			len = BIO_read(web, buff, sizeof(buff));
			if (len > 0) {
				BIO_write(out, buff, len);
			}
		} while (len > 0 || BIO_should_retry(web));

		if (out)
			BIO_free(out);

		if (web != nullptr)
			BIO_free_all(web);

		if (nullptr != ctx)
			SSL_CTX_free(ctx);
	}
};

int main(int argc, char *argv[]) {
	SSL_library_init();

	Client client;
	client.init();
	client.connect("www.google.com", "443");

	Client client2;
	client2.init();
	client2.connect("localhost", "4433");
}