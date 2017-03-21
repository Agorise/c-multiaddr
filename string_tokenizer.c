#include <stdlib.h>
#include <string.h>

/**
 * A replacement strtok_r so we can compile with c99
 * @param str the original string
 * @param delim the delimiters
 * @param nextp used internally to save state
 * @returns a pointer to the next element
 */
char* ma_utils_strtok_r(char *str, const char *delim, char **nextp)
{
    char *ret;

    if (str == NULL)
    {
        str = *nextp;
    }

    str += strspn(str, delim);

    if (*str == '\0')
    {
        return NULL;
    }

    ret = str;

    str += strcspn(str, delim);

    if (*str)
    {
        *str++ = '\0';
    }

    *nextp = str;

    return ret;
}
