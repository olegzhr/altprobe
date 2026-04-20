/*
 *   Copyright 2021 Oleg Zharkov
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

#include <iostream>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <algorithm>
#include <sys/wait.h>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>

#include "cobject.h"
#include "workspace.h"

namespace {
    // Default permissions for newly created directories (rwxr-xr-x)
    const mode_t DEFAULT_DIR_MODE = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
}

bool IsDirectoryEmpty(const string& path) {
    
    // Open directory for scanning
    DIR *dir = opendir(path.c_str());
    if (!dir) {
        return false;
    }

    bool isEmpty = true;
    struct dirent *ent;
    
    // Scan directory contents
    while ((ent = readdir(dir)) != nullptr) {
        string itemName = ent->d_name;
        
        // Ignore current and parent directory entries
        if (itemName != "." && itemName != "..") {
            isEmpty = false;
            break;
        }
    }
    closedir(dir);

    return isEmpty;
}


/**
 * Checks if the given path is a root directory ("/").
 * Returns true if path is root (preventing dangerous deletions).
 */
bool isRootDirectory(const std::string& path) {
    return path == "/";
}

/**
 * Deletes a single file or empty directory.
 * Returns true on success, false on failure.
 */
bool deleteFileOrDir(const std::string& path) {
    struct stat statbuf;

    // Get file/directory metadata
    if (lstat(path.c_str(), &statbuf) != 0) {
        return false;
    }

    // Handle directory deletion (must be empty)
    if (S_ISDIR(statbuf.st_mode)) {
        if (rmdir(path.c_str()) != 0) {
            return false;
        }
    }
    // Handle file deletion
    else {
        if (unlink(path.c_str()) != 0) {
            return false;
        }
    }

    return true;
}

/**
 * Recursively deletes all contents of a directory (files/subdirectories).
 * Returns true if all deletions succeeded.
 */
bool clearDirectoryContents(const std::string& dirPath) {
    DIR* dir = opendir(dirPath.c_str());
    if (!dir) {
        return false;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        // Skip "." (current dir) and ".." (parent dir)
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        std::string fullPath = dirPath + "/" + entry->d_name;

        // Recursively clear subdirectories
        if (entry->d_type == DT_DIR) {
            clearDirectoryContents(fullPath);  // Recurse into subdirectory
        }

        // Delete the file or now-empty subdirectory
        deleteFileOrDir(fullPath);
    }

    closedir(dir);
    return true;
}

/**
 * Safely clears a directory after verifying it's not root.
 * Returns true if directory was successfully cleared.
 */
void ClearWorkspace(const string& dirPath) {
    // Critical safety check
    if (isRootDirectory(dirPath)) {
        return;
    }

    clearDirectoryContents(dirPath);
}

bool IsDirectory(const string& path) {
    struct stat statbuf;
    if (stat(path.c_str(), &statbuf) != 0) {
        return false;
    }
    return S_ISDIR(statbuf.st_mode);
}

bool EnsureDirectoryExists(const string& path) {
    struct stat st;
    // Check if directory exists
    if (stat(path.c_str(), &st) == -1) {
        // Create directory with secure permissions if doesn't exist
        if (mkdir(path.c_str(), DEFAULT_DIR_MODE) == -1) {
            return false;
        }
    }
    
    return true;
}

bool IsWritableDirectory(const string& path) {
    return access(path.c_str(), W_OK) == 0;
}

void EnsureTrailingSlash(string& str) {
    if (!str.empty() && str.back() != '/') {
        str += '/';
    }
}

string CombinePaths(const string& a, const string& b) {
    // Remove trailing slashes from first path
    std::string path_a = a;
    while (!path_a.empty() && path_a.back() == '/') {
        path_a.pop_back();
    }
    
    // Remove leading slashes from second path
    std::string path_b = b;
    while (!path_b.empty() && path_b.front() == '/') {
        path_b.erase(0, 1);
    }
    
    // Combine with single separator
    if (path_a.empty()) return path_b;
    if (path_b.empty()) return path_a;
    
    return path_a + '/' + path_b;
}

// Function to check if a path exists
bool PathExists(const string& path) {
    struct stat info;
    return stat(path.c_str(), &info) == 0;
}

// Function to create a directory
bool CreateDirectory(const string& path) {
    // Create directory with read/write/search permissions for owner and group,
    // and read/search permissions for others
    int status = mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    return status == 0;
}