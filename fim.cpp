#include <openssl/evp.h>

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <ctime>

namespace fs = std::filesystem;
using HashMap = std::map<std::string, std::string>;

std::string sha256(const fs::path& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filePath.string());
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Unable to create SHA-256 context.");

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA-256 initialization failed.");
    }

    std::vector<char> buffer(1024 * 1024);

    while (file) {
        file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        std::streamsize bytesRead = file.gcount();

        if (bytesRead > 0 &&
            EVP_DigestUpdate(ctx, buffer.data(),
                             static_cast<size_t>(bytesRead)) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("SHA-256 update failed.");
        }
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLength = 0;

    if (EVP_DigestFinal_ex(ctx, digest, &digestLength) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA-256 finalization failed.");
    }

    EVP_MD_CTX_free(ctx);

    std::ostringstream result;
    result << std::hex << std::setfill('0');

    for (unsigned int i = 0; i < digestLength; ++i)
        result << std::setw(2) << static_cast<int>(digest[i]);

    return result.str();
}

HashMap scanDirectory(const fs::path& directory,
                      const fs::path& excludedFile = {}) {
    HashMap files;

    if (!fs::exists(directory) || !fs::is_directory(directory))
        throw std::runtime_error("Invalid directory: " + directory.string());

    fs::path excludedAbsolute;
    if (!excludedFile.empty())
        excludedAbsolute = fs::absolute(excludedFile).lexically_normal();

    for (const auto& entry : fs::recursive_directory_iterator(directory)) {
        if (!entry.is_regular_file()) continue;

        fs::path absolutePath = fs::absolute(entry.path()).lexically_normal();

        if (!excludedFile.empty() && absolutePath == excludedAbsolute)
            continue;

        std::string relativePath =
            fs::relative(entry.path(), directory).generic_string();

        files[relativePath] = sha256(entry.path());
    }

    return files;
}

bool saveBaseline(const fs::path& baselinePath, const HashMap& records) {
    fs::create_directories(baselinePath.parent_path());

    std::ofstream out(baselinePath);
    if (!out) return false;

    for (const auto& [path, hash] : records)
        out << path << '\t' << hash << '\n';

    return true;
}

HashMap loadBaseline(const fs::path& baselinePath) {
    HashMap records;
    std::ifstream in(baselinePath);

    if (!in)
        throw std::runtime_error(
            "Baseline not found. Run: ./fim baseline <directory>");

    std::string path, hash;

    while (std::getline(in, path, '\t') && std::getline(in, hash)) {
        records[path] = hash;
    }

    return records;
}

void printSection(const std::string& title,
                  const std::vector<std::string>& items) {
    std::cout << "\n" << title << ":\n";

    if (items.empty()) {
        std::cout << "  None\n";
        return;
    }

    for (const auto& item : items)
        std::cout << "  " << item << '\n';
}

std::string createReport(const fs::path& directory,
                         const std::vector<std::string>& created,
                         const std::vector<std::string>& modified,
                         const std::vector<std::string>& deleted) {
    std::ostringstream report;

    report << "FILE INTEGRITY CHECK\n";
    report << "====================\n";
    report << "Directory: " << fs::absolute(directory).string() << "\n";

    printSection("MODIFIED", modified);
    printSection("CREATED", created);
    printSection("DELETED", deleted);

    bool changed = !created.empty() ||
                   !modified.empty() ||
                   !deleted.empty();

    report << "\nStatus: "
           << (changed ? "CHANGES DETECTED" : "NO CHANGES DETECTED")
           << '\n';

    return report.str();
}

int createBaseline(const fs::path& directory) {
    fs::path baselinePath = directory / "baseline.db";

    HashMap records = scanDirectory(directory, baselinePath);

    if (!saveBaseline(baselinePath, records))
        throw std::runtime_error("Unable to save baseline.");

    std::cout << "Baseline created successfully.\n";
    std::cout << "Files recorded: " << records.size() << '\n';
    std::cout << "Baseline: " << baselinePath << '\n';

    return 0;
}

int checkIntegrity(const fs::path& directory,
                   const fs::path& reportPath = {}) {
    fs::path baselinePath = directory / "baseline.db";

    HashMap baseline = loadBaseline(baselinePath);
    HashMap current = scanDirectory(directory, baselinePath);

    std::vector<std::string> created;
    std::vector<std::string> modified;
    std::vector<std::string> deleted;

    for (const auto& [path, hash] : current) {
        auto old = baseline.find(path);

        if (old == baseline.end())
            created.push_back(path);
        else if (old->second != hash)
            modified.push_back(path);
    }

    for (const auto& [path, hash] : baseline) {
        if (current.find(path) == current.end())
            deleted.push_back(path);
    }

    std::string report =
        createReport(directory, created, modified, deleted);

    std::cout << report;

    if (!reportPath.empty()) {
        std::ofstream out(reportPath);

        if (!out)
            throw std::runtime_error("Unable to write report.");

        out << report;
        std::cout << "\nReport saved to: " << reportPath << '\n';
    }

    return (created.empty() && modified.empty() && deleted.empty()) ? 0 : 1;
}

void printUsage(const char* program) {
    std::cout << "\nFile Integrity Monitoring System\n\n";
    std::cout << "Usage:\n";
    std::cout << "  " << program << " baseline <directory>\n";
    std::cout << "  " << program << " check <directory>\n";
    std::cout << "  " << program
              << " check <directory> <report-file>\n\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 4) {
        printUsage(argv[0]);
        return 1;
    }

    try {
        std::string command = argv[1];
        fs::path directory = argv[2];

        if (command == "baseline" && argc == 3)
            return createBaseline(directory);

        if (command == "check") {
            fs::path report;

            if (argc == 4)
                report = argv[3];

            return checkIntegrity(directory, report);
        }

        printUsage(argv[0]);
        return 1;

    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << '\n';
        return 2;
    }
}
