/*
 * see: http://stackoverflow.com/questions/11705815/client-and-server-communication-using-ssl-c-c-ssl-protocol-dont-works
 */
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

using namespace std;

class Server {
	unsigned long ssl_err = 0;
	SSL_CTX *ctx;
	int sock = 0;

public:
	void initSSL() {
		ctx = SSL_CTX_new(TLSv1_method());
		ssl_err = ERR_get_error();
		if(!(ctx != nullptr)) {
			cerr << ssl_err << " [Error] SSL_CTX_new" << endl;
			return; /* failed */
		}
	}

	void initCert(const char *cert, const char *key) {
		int res = 0;

		res = SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM);
		if (res != 1) { cerr << res << " [Error] SSL_CTX_use_certificate_file" << endl; return; }

		res = SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
		if (res != 1) { cerr << res << " [Error] SSL_CTX_use_PrivateKey_file" << endl; return; }

		res = SSL_CTX_check_private_key(ctx);
		if (res != 1) { cerr << res << " [Error] SSL_CTX_check_private_key" << endl; return; }
	}

	void doListen(int port) {
		struct sockaddr_in addr;
		bzero(&addr, sizeof(addr));

		sock = socket(PF_INET, SOCK_STREAM, 0);

		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = INADDR_ANY;

		if ( bind(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
			perror("can't bind port");
			return;
		}

		if ( listen(sock, 10) != 0 ) {
			perror("Can't configure listening port");
			return;
		}
	}

	void doRead() {
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		SSL *ssl;

		int client = accept(sock, (struct sockaddr*)&addr, &len);
		printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);

		doTLSReadAndWrite(ssl);

		close(client);
		SSL_free(ssl);
	}

	void doTLSReadAndWrite(SSL *ssl) {
		int bytes = 0;
		char buf[1024];
		int bufidx = 0;
		const char *payload = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\nHello\n";

		if (SSL_accept(ssl) != 1) {
			ERR_print_errors_fp(stderr);
			return;
		}

		const SSL_SESSION *session = SSL_get_session(ssl);
		if (session != nullptr) {
			SSL_SESSION_print_fp(stdout, session);
		}

		while (1) {
			bytes = SSL_read(ssl, buf+bufidx, sizeof(buf)-bufidx);
			if (bytes > 0) {
				bufidx = bufidx + bytes;
				buf[bufidx] = '\0';
			} else {
				ERR_print_errors_fp(stderr);
				break;
			}
			if (strcmp("\r\n\r\n", buf+bufidx-4) == 0) break;
			if (strcmp("\n\n", buf+bufidx-2) == 0) break;
		}
		cout << "SSL_read(): " << buf << endl;

		cout << "SSL_write(): " << payload << endl;
		SSL_write(ssl, payload, strlen(payload));
	}

	void doClose() {
		SSL_CTX_free(ctx);
		close(sock);
	}
};

int main(int argc, char *argv[])
{
	SSL_library_init();

	Server server;
	server.initSSL();
	server.initCert("cert.pem", "key.pem");
	server.doListen(4433);
	server.doRead();
	server.doClose();

	return 0;
}