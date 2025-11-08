// client.cpp
// Compile: g++ -std=c++17 client.cpp -o client -lssl -lcrypto
// Run: ./client <server_ip> <port>
// Simple interactive client matching server protocol.
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
const std::string SERVER_SALT = "S3rv3rS@lt";

std::string sha256_hex(const std::string &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)data.data(), data.size(), hash);
    std::ostringstream oss;
    oss << std::hex;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss.width(2); oss.fill('0');
        oss << (int)hash[i];
    }
    return oss.str();
}

std::vector<unsigned char> sha256_bin(const std::string &data) {
    std::vector<unsigned char> out(SHA256_DIGEST_LENGTH);
    SHA256((const unsigned char*)data.data(), data.size(), out.data());
    return out;
}

std::vector<unsigned char> derive_key(const std::string &username, const std::string &password) {
    return sha256_bin(username + password + SERVER_SALT);
}

std::vector<unsigned char> aes_ctr_crypt(const std::vector<unsigned char> &in, const std::vector<unsigned char> &key) {
    std::vector<unsigned char> out(in.size());
    unsigned char iv[16]; memset(iv,0,16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen=0, tmplen=0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key.data(), iv);
    EVP_EncryptUpdate(ctx, out.data(), &outlen, in.data(), in.size());
    EVP_EncryptFinal_ex(ctx, out.data()+outlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

bool send_all(int sock, const void *buf, size_t len) {
    const char *p = (const char*)buf;
    size_t sent=0;
    while (sent < len) {
        ssize_t n = send(sock, p+sent, len-sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

bool recv_all(int sock, void *buf, size_t len) {
    char *p = (char*)buf;
    size_t recvd=0;
    while (recvd < len) {
        ssize_t n = recv(sock, p+recvd, len-recvd, 0);
        if (n <= 0) return false;
        recvd += n;
    }
    return true;
}

bool send_line(int sock, const std::string &line) {
    std::string s = line + "\n";
    return send_all(sock, s.data(), s.size());
}

bool recv_line(int sock, std::string &out) {
    out.clear();
    char c;
    while (true) {
        ssize_t n = recv(sock, &c, 1, 0);
        if (n <= 0) return false;
        if (c == '\n') break;
        out.push_back(c);
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: ./client <server_ip> <port>\n";
        return 1;
    }
    std::string server = argv[1];
    int port = atoi(argv[2]);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }
    struct sockaddr_in servaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    if (inet_pton(AF_INET, server.c_str(), &servaddr.sin_addr) <= 0) { perror("inet_pton"); return 1; }
    if (connect(sock, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) { perror("connect"); return 1; }
    std::string username, password;
    std::cout << "Username: "; std::getline(std::cin, username);
    std::cout << "Password: "; std::getline(std::cin, password);
    send_line(sock, "AUTH " + username + " " + password);
    std::string resp;
    if (!recv_line(sock, resp)) { std::cerr << "No response\n"; close(sock); return 1; }
    if (resp.rfind("OK",0) != 0) { std::cerr << "Auth failed: " << resp << "\n"; close(sock); return 1; }
    std::cout << "Authenticated.\n";
    auto key = derive_key(username, password);
    // interactive
    while (true) {
        std::cout << "command (list/download/upload/quit): ";
        std::string line; std::getline(std::cin, line);
        if (line.empty()) continue;
        std::istringstream iss(line); std::string cmd; iss >> cmd;
        if (cmd == "list") {
            send_line(sock, "LIST");
            while (true) {
                std::string l; if (!recv_line(sock,l)) { std::cerr<<"Connection closed\n"; return 0; }
                if (l == "END") break;
                std::cout << l << "\n";
            }
        } else if (cmd == "download") {
            std::string fname; iss >> fname;
            if (fname.empty()) { std::cout<<"Usage: download <filename>\n"; continue; }
            send_line(sock, "DOWNLOAD " + fname);
            std::string header; if (!recv_line(sock, header)) { std::cerr<<"No response\n"; break; }
            if (header.rfind("ERR",0) == 0) { std::cout << header << "\n"; continue; }
            // header: SIZE n
            std::istringstream hs(header); std::string tag; uint64_t n; hs >> tag >> n;
            std::vector<unsigned char> enc(n);
            if (!recv_all(sock, enc.data(), n)) { std::cerr<<"Failed to receive file\n"; break; }
            auto data = aes_ctr_crypt(enc, key);
            std::ofstream out(fname, std::ios::binary);
            out.write((const char*)data.data(), data.size());
            std::cout << "Downloaded " << fname << " (" << data.size() << " bytes)\n";
        } else if (cmd == "upload") {
            std::string path; iss >> path;
            if (path.empty()) { std::cout<<"Usage: upload <local_path>\n"; continue; }
            if (!fs::exists(path)) { std::cout<<"File not found\n"; continue; }
            uint64_t n = fs::file_size(path);
            std::string fname = fs::path(path).filename().string();
            send_line(sock, "UPLOAD " + fname + " " + std::to_string(n));
            std::string ready; if (!recv_line(sock, ready)) break;
            if (ready.rfind("READY",0) != 0) { std::cout<<"Server error: "<<ready<<"\n"; continue; }
            std::ifstream in(path, std::ios::binary);
            std::vector<unsigned char> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            auto enc = aes_ctr_crypt(data, key);
            if (!send_all(sock, enc.data(), enc.size())) { std::cerr<<"Send failed\n"; break; }
            std::string done; if (!recv_line(sock, done)) break;
            std::cout << done << "\n";
        } else if (cmd == "quit") {
            send_line(sock, "QUIT");
            std::string bye; if (recv_line(sock, bye)) std::cout<<bye<<"\n";
            break;
        } else {
            std::cout << "Unknown command\n";
        }
    }
    close(sock);
    return 0;
}
