#include <algorithm>
#include <fstream>
#include <string>
#include <vector>
#include <cassert>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <experimental/filesystem>

using namespace std;
namespace fs = std::experimental::filesystem;

struct UsageInfo {
    long long user_time;
    long long kernel_time;
    long long pass_time;
    long long memory;
    int exit_code;
    int signal;

    string verbose(string name) {
        char buffer[1024];
        sprintf(buffer, "%s {user:%lld,kernel:%lld,pass:%lld,memory:%lld,exit:%d,signal:%d}",
                name.c_str(), user_time, kernel_time, pass_time, memory, exit_code, signal);
        return buffer;
    }
};

string current_path() {
    return fs::current_path().string();
}

string getFileName(string nameBase, string ext) {
    return current_path() + "/run/" + nameBase + "." + ext;
}

string readFile(string fileName) {
    std::ifstream t(fileName);
    return std::string((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
}

void recreateDirectory(string directory) {
    fs::remove_all(directory);
    fs::create_directory(directory);
}

UsageInfo getUsageInfo(string nameBase) {
    std::ifstream ifs(getFileName(nameBase, "output") + "/usage");
    string tag; long long i;
    UsageInfo ret;
    int cnt = 0;
    while (ifs >> tag >> i) {
        cnt++;
        if (tag == "user") {
            ret.user_time = i;
        } else if (tag == "kernel") {
            ret.kernel_time = i;
        } else if (tag == "pass") {
            ret.pass_time = i;
        } else if (tag == "memory") {
            ret.memory = i;
        } else if (tag == "exit") {
            ret.exit_code = i;
        } else if (tag == "signal") {
            ret.signal = i;
        }
    }
    assert (cnt == 6);
    return ret;
}

// trim from start (in place)
static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

// trim from both ends (in place)
static inline void _trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

// trim from both ends (copying)
static inline std::string trim(std::string s) {
    _trim(s);
    return s;
}