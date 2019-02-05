#include <string>
#include <vector>
#include <cassert>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
using namespace std;

#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include <catch2/catch.hpp>

inline bool check_file_exists(const std::string& name) {
    ifstream f(name.c_str());
    return f.good();
}

const char *convert(const std::string& s) {
    return s.c_str();
}

string getCurrentWorkingDir() {
    char currentWorkingDirectory[1024];
    getcwd(currentWorkingDirectory, 1024);
    return currentWorkingDirectory;
}

void execute(string directory,
             string commandLine,
             vector<string> args,
             long long memoryLimit, // in megabytes
             long long timeLimit,   // in milliseconds
             string nameBase,
             int stdin = -1, int stdout = -1, int stderr = -1) {
    pid_t pid = fork();
    REQUIRE (pid >= 0);
    if (pid == 0) {
        // getCurrentWorkingDir() + "/run/root"
        vector<string> nsjail_args = {"./nsjail", "-Mo",
                                      "--chroot", directory,
                                      "--user", "99999", "--group", "99999",
                                      "--log", getCurrentWorkingDir() + "/run/" + nameBase + ".log",
                                      "--usage", getCurrentWorkingDir() + "/run/" + nameBase + ".usage",
                                      "-R", "/bin",
                                      "-R", "/lib",
                                      "-R", "/lib64",
                                      "-R", "/usr",
                                      "-R", "/sbin",
                                      "-T", "/dev",
                                      "-R", "/dev/urandom",
                                      "--cgroup_pids_max", "1024",
                                      "--cgroup_cpu_ms_per_sec", "1000",
                                      "--set_cpus", "1",
                                      "--cgroup_mem_max", to_string((memoryLimit + 32) * 1024 * 1024),
                                      "--time_limit", to_string((timeLimit * 2 + 1000) / 1000),
                                      "--rlimit_cpu", to_string((timeLimit + 1000) / 1000),
                                      "--rlimit_stack", to_string(memoryLimit + 32),
                                      "--rlimit_fsize", to_string(memoryLimit + 256),
                                      };

        /* redirect input and output */
        string redirectStdinFile = "./run/" + nameBase + ".in";
        if (check_file_exists(redirectStdinFile)) {
            nsjail_args.push_back("--stdin_redirect_fd");
            stdin = open(redirectStdinFile.c_str(), O_RDONLY);
            nsjail_args.push_back(to_string(stdin));
        } else {
            nsjail_args.push_back("--stdin_from_null");
        }

        stdout = open(("./run/" + nameBase + ".out").c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
        if (stdout == -1) {
            perror("Open stdout failed");
            REQUIRE (stdout != -1);
        }
        nsjail_args.push_back("--stdout_redirect_fd");
        nsjail_args.push_back(to_string(stdout));

        stderr = open(("./run/" + nameBase + ".err").c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
        REQUIRE (stderr != -1);
        nsjail_args.push_back("--stderr_redirect_fd");
        nsjail_args.push_back(to_string(stderr));

        nsjail_args.push_back("--");
        nsjail_args.push_back(commandLine);
        for (const string &s: args) nsjail_args.push_back(s);

        char* * nsjail_args_array = new char*[nsjail_args.size() + 1];
        for (size_t i = 0; i < nsjail_args.size(); ++i) {
            nsjail_args_array[i] = new char[nsjail_args[i].length() + 1];
            strcpy(nsjail_args_array[i], nsjail_args[i].c_str());

//            printf("%s\n", nsjail_args[i].c_str());
        }
        nsjail_args_array[nsjail_args.size()] = nullptr;

        if (execve("./nsjail", nsjail_args_array, NULL) == -1) {
            perror("Error on execve");
            REQUIRE (0);
        }
    } else {
        int wpid, status;
        REQUIRE (waitpid(pid, &status, 0) == pid);
        REQUIRE (status == 0);
    }
}

void compile() {

}

TEST_CASE("Process info", "[system]") {
    execute("/", "/bin/ps", {"aux"}, 32, 500, "processInfo");
}

TEST_CASE("Shutdown", "[system]") {

}

TEST_CASE("Args", "[success]") {
//    execute("", "", {}, 0, 0, "");
}
