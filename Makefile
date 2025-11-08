CXX = g++
CXXFLAGS = -std=c++17 -O2
LIBS = -lssl -lcrypto -lpthread

all: server client

server: server.cpp
	$(CXX) $(CXXFLAGS) server.cpp -o server $(LIBS)

client: client.cpp
	$(CXX) $(CXXFLAGS) client.cpp -o client $(LIBS)

clean:
	rm -f server client
