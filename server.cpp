// server.cpp
// Compile: g++ -std=c++17 server.cpp -o server -lssl -lcrypto -lpthread
// Run: ./server <port>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

const std::string STORAGE_DIR = "server_storage";
const std::string USERS_FILE = "users.txt";
const std::string SERVER_SALT = "S3rv3rS@lt";

std::mutex cout_mtx;
std::atomic<bool> running(true);

void safe_print(const std::string &s) {
    std::lock_guard<std::mutex> lg(cout_mtx);
    std::cout << s << std::endl;
}

bool ensure_storage() {
    try {
        if (!fs::exists(STORAGE_DIR)) fs::create_directory(STORAGE_DIR);
        return true;
    } catch (...) {
        return false;
    }
}

struct UserRecord { std::string user, password; };

std::vector<UserRecord> load_users() {
    std::vector<UserRecord> users;
    std::ifstream f(USERS_FILE);
    if (!f.is_open()) {
        // create default plain-text user
        std::ofstream out(USERS_FILE);
        out << "test password123\n";
        out.close();
        users.push_back({"test", "password123"});
        return users;
    }
    std::string u, p;
    while (f >> u >> p) users.push_back({u, p});
    return users;
}

bool find_user(const std::vector<UserRecord>& users, const std::string &username, const std::string &password) {
    for (auto &u: users)
        if (u.user == username && u.password == password)
            return true;
    return false;
}

// derive AES-256 key from username+password+SERVER_SALT
std::vector<unsigned char> sha256_bin(const std::string &data) {
    std::vector<unsigned char> out(SHA256_DIGEST_LENGTH);
    SHA256((const unsigned char*)data.data(), data.size(), out.data());
    return out;
}
std::vector<unsigned char> derive_key(const std::string &username, const std::string &password) {
    return sha256_bin(username + password + SERVER_SALT);
}

// AES-CTR encrypt/decrypt
std::vector<unsigned char> aes_ctr_crypt(const std::vector<unsigned char> &in, const std::vector<unsigned char> &key) {
    std::vector<unsigned char> out(in.size());
    unsigned char iv[16]; memset(iv, 0, 16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen=0, tmplen=0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key.data(), iv);
    EVP_EncryptUpdate(ctx, out.data(), &outlen, in.data(), in.size());
    EVP_EncryptFinal_ex(ctx, out.data()+outlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

ssize_t send_all(int sock, const void *buf, size_t len) {
    const char *p = (const char*)buf;
    size_t sent=0;
    while (sent < len) {
        ssize_t n = send(sock, p+sent, len-sent, 0);
        if (n <= 0) return n;
        sent += n;
    }
    return sent;
}

bool send_line(int sock, const std::string &line) {
    std::string s = line + "\n";
    return send_all(sock, s.data(), s.size()) == (ssize_t)s.size();
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

void handle_client(int client_sock, std::vector<UserRecord> users) {
    safe_print("Client connected");
    std::string line;
    if (!recv_line(client_sock, line)) { close(client_sock); return; }

    std::istringstream iss(line);
    std::string cmd, username, password;
    iss >> cmd >> username >> password;
    if (cmd != "AUTH" || username.empty() || password.empty()) {
        send_line(client_sock, "ERR Invalid AUTH format");
        close(client_sock);
        return;
    }

    if (!find_user(users, username, password)) {
        send_line(client_sock, "ERR Invalid credentials");
        close(client_sock);
        return;
    }

    send_line(client_sock, "OK");
    auto key = derive_key(username, password);

    // command loop
    while (true) {
        if (!recv_line(client_sock, line)) break;
        std::istringstream cs(line);
        cs >> cmd;

        if (cmd == "LIST") {
            for (auto &p: fs::directory_iterator(STORAGE_DIR)) {
                if (p.is_regular_file()) {
                    send_line(client_sock, p.path().filename().string());
                }
            }
            send_line(client_sock, "END");

        } else if (cmd == "DOWNLOAD") {
            std::string fname; cs >> fname;
            fs::path fp = fs::path(STORAGE_DIR) / fname;
            if (!fs::exists(fp)) { send_line(client_sock, "ERR File not found"); continue; }
            std::ifstream f(fp, std::ios::binary);
            std::vector<unsigned char> data((std::istreambuf_iterator<char>(f)), {});
            auto enc = aes_ctr_crypt(data, key);
            uint64_t n = enc.size();
            std::ostringstream hdr; hdr << "SIZE " << n;
            send_line(client_sock, hdr.str());
            send_all(client_sock, enc.data(), enc.size());

        } else if (cmd == "UPLOAD") {
            std::string fname; uint64_t n;
            cs >> fname >> n;
            if (fname.empty()) { send_line(client_sock, "ERR Bad filename"); continue; }
            send_line(client_sock, "READY");
            std::vector<unsigned char> enc(n);
            size_t recvd = 0;
            while (recvd < n) {
                ssize_t r = recv(client_sock, enc.data()+recvd, n-recvd, 0);
                if (r <= 0) break;
                recvd += r;
            }
            auto data = aes_ctr_crypt(enc, key);
            std::ofstream out(fs::path(STORAGE_DIR)/fname, std::ios::binary);
            out.write((const char*)data.data(), data.size());
            send_line(client_sock, "OK Uploaded");

        } else if (cmd == "QUIT") {
            send_line(client_sock, "OK Bye");
            break;
        } else {
            send_line(client_sock, "ERR Unknown command");
        }
    }

    close(client_sock);
    safe_print("Client disconnected");
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 2) {
        std::cerr << "Usage: ./server <port>\n";
        return 1;
    }

    int port = atoi(argv[1]);
    ensure_storage();
    auto users = load_users();

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(listen_fd, 10) < 0) { perror("listen"); return 1; }

    safe_print("Server listening on port " + std::to_string(port));

    while (running) {
        struct sockaddr_in cliaddr{};
        socklen_t clilen = sizeof(cliaddr);
        int client_fd = accept(listen_fd, (struct sockaddr*)&cliaddr, &clilen);
        if (client_fd < 0) { perror("accept"); continue; }
        std::thread t(handle_client, client_fd, users);
        t.detach();
    }

    close(listen_fd);
    return 0;
}

