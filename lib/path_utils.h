#ifndef PATH_UTILS_H
#define PATH_UTILS_H

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <ctype.h>
#include <linux/limits.h>

/**
 * Extracts the filename from a given path.
 * Supports UTF-8 and standard Linux paths.
 * 
 * Example: "/home/user/file.txt" -> "file.txt"
 * 
 * @param path The full path string.
 * @return A pointer to the start of the filename in the given string.
 */
static inline const char* get_filename(const char* path) {
    if (!path || !*path) return "";
    
    // In UTF-8, 0x2F ('/') is unique and doesn't appear in other multibyte sequences.
    const char* last_slash = strrchr(path, '/');
    if (last_slash) {
        return last_slash + 1;
    }
    return path;
}

/**
 * Extracts the directory component of the path.
 * The caller must free the returned string.
 * 
 * Example: "/home/user/file.txt" -> "/home/user"
 * 
 * @param path The full path string.
 * @return A newly allocated string containing the directory path, or NULL on error.
 */
static inline char* get_directory(const char* path) {
    if (!path) return NULL;
    
    const char* last_slash = strrchr(path, '/');
    if (!last_slash) {
        // No slash, implies current directory
        return strdup("."); 
    }
    
    if (last_slash == path) {
        // Root directory "/"
        return strdup("/");
    }
    
    size_t len = last_slash - path;
    char* dir = (char*)malloc(len + 1);
    if (dir) {
        strncpy(dir, path, len);
        dir[len] = '\0';
    }
    return dir;
}

/**
 * Checks if the string contains special characters that might be unsafe for 
 * basic display or shell usage without escaping.
 * Note: Linux allows almost anything except '/' and null in filenames.
 * This checks for control characters which are generally unsafe/confusing.
 * 
 * @param str The string to check.
 * @return 1 if unsafe characters are found, 0 otherwise.
 */
static inline int has_unsafe_chars(const char* str) {
    if (!str) return 0;
    while (*str) {
        unsigned char c = (unsigned char)*str;
        if (c < 32) return 1; // Control characters
        str++;
    }
    return 0;
}

/**
 * Resolves the absolute path.
 * Wrapper around realpath.
 * 
 * @param relative_path Input path.
 * @param resolved_path Buffer to hold the result (must be PATH_MAX).
 * @return resolved_path on success, NULL on failure.
 */
static inline char* resolve_path(const char* relative_path, char* resolved_path) {
    return realpath(relative_path, resolved_path);
}

/**
 * Sanitizes the filename by replacing special characters with '-'.
 * Keeps alphanumeric characters, dots (.), hyphens (-), and underscores (_).
 * 
 * @param str The string to sanitize (modified in place).
 */
static inline void sanitize_filename(char* str) {
    if (!str) return;
    for (char* p = str; *p; p++) {
        unsigned char c = (unsigned char)*p;
        // Allow alphanumeric, dots, hyphens, underscores, and high-bit bytes (UTF-8)
        if (!isalnum(c) && c != '.' && c != '-' && c != '_' && c <= 127) {
            *p = '-';
        }
    }
}

#endif
