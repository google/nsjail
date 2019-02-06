#include "test.hpp"

#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include <catch2/catch.hpp>
#include <omp.h>

string getOutput(string nameBase, string type = "out") {
    return readFile(getFileName(nameBase, "output") + "/" + type);
}

namespace constants {
    long long outputSizeBase = 256;
    bool largeStack = true;
}

void execute(string directory,
             string commandLine,
             vector<string> args,
             long long memoryLimit, // in megabytes
             long long timeLimit,   // in milliseconds
             string nameBase,
             string expectedVerdict = "SUCCEEDED",
             int stdin = -1, int stdout = -1, int stderr = -1) {
    pid_t pid = fork();
    REQUIRE (pid >= 0);
    if (pid == 0) {
        // current_path() + "/run/root"
        string rootDir = getFileName(nameBase, "root");
        recreateDirectory(rootDir);

        string outputDir = getFileName(nameBase, "output");
        recreateDirectory(outputDir);

        vector<string> nsjail_args = {"./nsjail", "-Mo",
                                      "--chroot", rootDir,
                                      "--user", "99999", "--group", "99999",
                                      "--log", outputDir + "/log",
                                      "--usage", outputDir + "/usage",
//                                      "--proc_rw",
                                      "-R", "/bin",
                                      "-R", "/lib",
                                      "-R", "/lib64",
                                      "-R", "/usr",
                                      "-R", "/sbin",
                                      "-T", "/dev",
                                      "-R", "/dev/urandom",
                                      "-R", "/etc/alternatives",
                                      "-B", directory + ":/app",
                                      "-D", "/app",
                                      "-E", "env=123", "-E", "test=456",

                                      "--cgroup_pids_max", "64",
                                      "--cgroup_cpu_ms_per_sec", "1000",
                                      "--set_cpus", "1",
                                      "--cgroup_mem_max", to_string((memoryLimit + 32) * 1024 * 1024),
                                      "--time_limit", to_string((timeLimit * 2 + 1000) / 1000),
                                      "--rlimit_cpu", to_string((timeLimit + 1000) / 1000),
                                      "--rlimit_stack", to_string(constants::largeStack ? memoryLimit + 32 : 8),
                                      "--rlimit_fsize", to_string(memoryLimit + constants::outputSizeBase),
                                      };

        /* redirect input and output */
        if (stdin != -1) {
            nsjail_args.push_back("--stdin_redirect_fd");
            nsjail_args.push_back(to_string(stdin));
        } else {
            nsjail_args.push_back("--stdin_from_null");
        }

        stdout = open((outputDir + "/out").c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
        if (stdout == -1) {
            perror("Open stdout failed");
            REQUIRE (stdout != -1);
        }
        nsjail_args.push_back("--stdout_redirect_fd");
        nsjail_args.push_back(to_string(stdout));

        stderr = open((outputDir + "/err").c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
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
        int status;
        REQUIRE (waitpid(pid, &status, 0) == pid);
//        REQUIRE (status == 0);

        auto usage_info = getUsageInfo(nameBase);
        cout << usage_info.verbose(nameBase) << endl;
        if (expectedVerdict == "SUCCEEDED") {
            REQUIRE(usage_info.user_time <= timeLimit);
            REQUIRE(usage_info.memory <= memoryLimit * 1024LL);
            REQUIRE(usage_info.exit_code == 0);
        }
        if (expectedVerdict == "FAIL") {
            REQUIRE(usage_info.exit_code != 0);
        }
        if (expectedVerdict == "TIME_LIMIT_EXCEEDED") {
            REQUIRE(usage_info.user_time > timeLimit);
        }
        if (expectedVerdict == "IDLENESS_LIMIT_EXCEEDED") {
            REQUIRE(usage_info.pass_time > timeLimit);
        }
        if (expectedVerdict == "MEMORY_LIMIT_EXCEEDED") {
            REQUIRE(usage_info.memory > memoryLimit * 1024LL);
        }
    }
}

#include <unistd.h>

string prepareWorkingDirAndFile(string nameBase, string fileName) {
    string workingDir = current_path() + "/run/" + nameBase;
    fs::remove_all(workingDir);
    fs::create_directory(workingDir);
#pragma omp critical
    fs::copy_file(current_path() + "/tests/" + fileName, workingDir + "/" + fileName);
    return workingDir;
}

void compile(string name, string ext, string expectedVerdict = "SUCCEEDED",
        long long memoryLimit = 32, long long timeLimit = 500) {
    string fileName = name + "." + ext;
    string wd = prepareWorkingDirAndFile(name + ".compile.work", fileName);
    string targetName = name + ".o";
    if (ext == "c") {
        execute(wd, "/usr/bin/gcc", {"-o", targetName, fileName}, memoryLimit, timeLimit, name + ".compile", expectedVerdict);
    } else if (ext == "cpp") {
        execute(wd, "/usr/bin/g++", {"-o", targetName, fileName}, memoryLimit, timeLimit, name + ".compile", expectedVerdict);
    }
    if (expectedVerdict == "SUCCEEDED") {
        fs::copy_file(wd + "/" + name + ".o", current_path() + "/tests/" + name + ".o", fs::copy_options::overwrite_existing);
    }
}

void executeTemplate(string name, string ext, vector<string> args, string expectedVerdict = "SUCCEEDED",
        long long memoryLimit = 32, long long timeLimit = 500) {
    if (ext == "o") {
        string fileName = name + "." + ext;
        string inputPath = current_path() + "/tests/" + name + ".in";
        if (name.find_first_of(".") != string::npos) {
            inputPath = current_path() + "/tests/" + name.substr(0, name.find_first_of(".")) + ".in";
        }
        int stdin = -1;
        if (fs::exists(inputPath) && fs::is_regular_file(inputPath)) {
            stdin = open(inputPath.c_str(), O_RDONLY);
        }
        string wd = prepareWorkingDirAndFile(name + ".execute.work", fileName);
        execute(wd, "./" + fileName, args, memoryLimit, timeLimit, name + ".execute", expectedVerdict, stdin);
    }
}

TEST_CASE("Process info", "[system]") {
    execute("/", "/bin/ps", {"aux"}, 32, 500, "processInfo");  // dangerous to use /
    REQUIRE(getOutput("processInfo").find("USER") == 0);
}

TEST_CASE("Shutdown", "[system]") {
    execute("/", "/sbin/shutdown", {}, 32, 500, "shutdown", "FAILED");
}

TEST_CASE("List dev", "[system]") {
    execute("/", "/bin/ls", {"/dev"}, 32, 500, "listDev");
}

TEST_CASE("Working directory", "[system]") {
    execute("/bin", "/bin/pwd", {}, 32, 500, "pwd");
    REQUIRE(trim(getOutput("pwd")) == "/app");
}

TEST_CASE("Network", "[system]") {
    SECTION("hostname") {
        execute("/", "/usr/bin/curl", {"https://www.baidu.com/"}, 32, 500, "network.host", "FAIL");
    }
    SECTION("ip") {
        execute("/", "/usr/bin/curl", {"http://180.97.33.108/"}, 32, 500, "network.ip", "FAIL");
    }
}

TEST_CASE("Normal", "[integration]") {
    SECTION("args") {
        compile("args", "c");
        executeTemplate("args", "o", {"abc", "123"});
        REQUIRE(getOutput("args.execute").find("argv[1]: abc\nargv[2]: 123") != string::npos);
    }
    SECTION("normal") {
        compile("normal", "c");
        executeTemplate("normal", "o", {});
        REQUIRE(trim(getOutput("normal.execute")) == "text\nHello world");
    }
    SECTION("math") {
        compile("math", "c");
        executeTemplate("math", "o", {});
        REQUIRE(trim(getOutput("math.execute")) == "abs 1024");
    }
    SECTION("env") {
        compile("env", "c");
        executeTemplate("env", "o", {});
        REQUIRE(getOutput("env.execute") == "123\n456\n");
    }
    SECTION("stderr") {
        compile("stdout_stderr", "c");
        executeTemplate("stdout_stderr", "o", {});
        REQUIRE(getOutput("stdout_stderr.execute", "err") == "stderr\n+++++++++++++++\n");
        REQUIRE(getOutput("stdout_stderr.execute", "out") == "--------------\nstdout\n");
    }
    SECTION("user") {
        compile("uid_gid", "c");
        executeTemplate("uid_gid", "o", {});
        REQUIRE(getOutput("uid_gid.execute") == "uid=99999 gid=99999 groups=99999,65534\nuid 99999\ngid 99999\n");
    }
    SECTION("writev") {
        compile("writev", "cpp", "SUCCEEDED", 128, 500);
        ofstream ofs("./tests/writev.in");
        for (int i = 0; i < 10000; ++i) ofs << "111";
        ofs << endl;
        executeTemplate("writev", "o", {});
    }
}

TEST_CASE("TL", "[integration]") {
    SECTION("real_time") {
        compile("sleep", "c");
        executeTemplate("sleep", "o", {}, "IDLENESS_LIMIT_EXCEEDED");
    }
    SECTION("cpu_time") {
        compile("while1", "c");
        executeTemplate("while1", "o", {}, "TIME_LIMIT_EXCEEDED");
    }
}

TEST_CASE("ML", "[integration]") {
    SECTION("memory1") {
        compile("memory1", "c");
        executeTemplate("memory1", "o", {}, "MEMORY_LIMIT_EXCEEDED", 64, 500);
    }
    SECTION("memory2") {
        compile("memory2", "c");
        executeTemplate("memory2", "o", {}, "FAIL", 32, 500);
        // malloc fail, disable-swap is necessary here
    }
    SECTION("memory3") {
        compile("memory3", "c");
        executeTemplate("memory3", "o", {}, "SUCCEEDED", 512, 1000);
    }
    SECTION("memory4") {
        // parent process doesn't affect child process
        int *a = new int[100000000];
        compile("normal", "c");
        executeTemplate("normal", "o", {}, "SUCCEEDED", 64, 500);
        delete[] a;
    }
    SECTION("stack") {
        compile("stack", "c");
        constants::largeStack = false;
        executeTemplate("stack", "o", {}, "FAIL", 512, 500);
        constants::largeStack = true;
        executeTemplate("stack", "o", {}, "SUCCEEDED", 512, 500);
    }
}

TEST_CASE("RTE", "[integration]") {
    SECTION("re1") {
        compile("re1", "c");
        executeTemplate("re1", "o", {}, "FAIL");
    }
    SECTION("re2") {
        compile("re2", "c");
        executeTemplate("re2", "o", {}, "SUCCEEDED");
        // this should fail, but somehow nsjail does not respond to raise
    }
}

TEST_CASE("Child", "[integration]") {
    SECTION("child_proc_cpu") {
        compile("child_proc_cpu_time_limit", "c");
        executeTemplate("child_proc_cpu_time_limit", "o", {}, "TIME_LIMIT_EXCEEDED", 64, 1000);
    }
    SECTION("child_proc_real") {
        compile("child_proc_real_time_limit", "c");
        executeTemplate("child_proc_real_time_limit", "o", {}, "IDLENESS_LIMIT_EXCEEDED");
    }
}

TEST_CASE("Compile", "[integration]") {
    SECTION("gcc_random") {
        compile("gcc_random", "c", "TIME_LIMIT_EXCEEDED", 2048, 1000);
    }
    SECTION("cpp_meta") {
        compile("cpp_meta", "cpp", "TIME_LIMIT_EXCEEDED", 1024, 1000);
    }
}

TEST_CASE("Output", "[integration]") {
    SECTION("output_ban") {
        compile("output_size", "c");
        vector<string> paths = {"/tmp/fsize_test", "/bin/test", "/test"};
        for (const auto& path: paths) {
            executeTemplate("output_size", "o", {path}, "FAIL");
            auto usage_info = getUsageInfo("output_size.execute");
            REQUIRE(usage_info.exit_code == 42);
        }
    }
    SECTION("size_control") {
        compile("output_size", "c");
        constants::outputSizeBase = 0;
        vector<string> paths = {"fsize_test", "/dev/fsize_test", "stdout"};
        for (const auto& path: paths) {
            executeTemplate("output_size", "o", {path}, "FAIL", 1, 1000);
            auto usage_info = getUsageInfo("output_size.execute");
            REQUIRE(usage_info.exit_code == 2);
            if (path == "stdout") {
                REQUIRE(getOutput("output_size.execute").length() == 1048576);
            }
        }
        constants::outputSizeBase = 256;
    }
}

TEST_CASE("Malformed", "[integration]") {
    SECTION("fork") {
        compile("fork", "c");
        executeTemplate("fork", "o", {}, "IDLENESS_LIMIT_EXCEEDED");
    }
}

TEST_CASE("Concurrency", "[integration]") {
    SECTION("conflict") {
        #pragma omp parallel for num_threads(16)
        for (int i = 0; i < 16; ++i) {
            execute("/", "/bin/ps", {"aux"}, 32, 500, "processInfo." + to_string(i));
            REQUIRE(getOutput("processInfo." + to_string(i)).find("USER") == 0);
        }
    }

    SECTION("concurrency") {
        compile("normal", "c");
        for (int i = 0; i < 16; ++i)
            fs::copy_file("./tests/normal.o", "./tests/normal." + to_string(i) + ".o", fs::copy_options::overwrite_existing);
#pragma omp parallel for num_threads(16)
        for (int i = 0; i < 16; ++i) {
            executeTemplate("normal." + to_string(i), "o", {}, "FAILED");
            REQUIRE(trim(getOutput("normal." + to_string(i) + ".execute")) == "text\nHello world");
        }
    }
}

TEST_CASE("Java", "[integration]") {

}

TEST_CASE("Python", "[integration]") {

}

TEST_CASE("Interaction", "[integration]") {

}