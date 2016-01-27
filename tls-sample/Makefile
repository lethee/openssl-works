all: client server cert.pem

cert.pem:
	# self-signed certificate
	openssl req -x509 -nodes -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -subj /C=KR/ST=Seoul/O=Sean/OU=Org/CN=www.localhost.com

server: server.cpp
	g++ -std=c++11 -Wall -o server server.cpp -lssl -lcrypto

client: client.cpp
	g++ -std=c++11 -Wall -o client client.cpp -lssl -lcrypto

test: all
	./server &
	./client
	./server &
	curl -v --insecure https://localhost:4433/

clean:
	rm -f cert.pem key.pem
	rm -f server
	rm -f client