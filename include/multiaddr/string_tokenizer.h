#pragma once

/**
 * A replacement strtok_r so we can compile with c99
 * @param str the original string
 * @param delim the delimiters
 * @param nextp used internally to save state
 * @returns a pointer to the next element
 */
char* ma_utils_strtok_r(char *str, const char *delim, char **nextp);
