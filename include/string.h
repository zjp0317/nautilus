#ifndef __STRING_H__
#define __STRING_H__

#define USE_NAUT_BUILTINS 1


#define isspace(c)      (c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v')
#define isascii(c)  (((c) & ~0x7f) == 0)
#define isupper(c)  ((c) >= 'A' && (c) <= 'Z')
#define islower(c)  ((c) >= 'a' && (c) <= 'z')
#define isalpha(c)  (isupper(c) || islower(c))
#define isdigit(c)  ((c) >= '0' && (c) <= '9')
#define isxdigit(c) (isdigit(c) \
                      || ((c) >= 'A' && (c) <= 'F') \
                      || ((c) >= 'a' && (c) <= 'f'))
#define isprint(c)  ((c) >= ' ' && (c) <= '~')

#define toupper(c)  ((c) - 0x20 * (((c) >= 'a') && ((c) <= 'z')))
#define tolower(c)  ((c) + 0x20 * (((c) >= 'A') && ((c) <= 'Z')))

#ifdef USE_NAUT_BUILTINS
void * memcpy (void * dst, const void * src, size_t n);
int memcmp (const void * s1_, const void * s2_, size_t n);
void * memset (void * dst, char c, size_t n);

size_t strlen (const char * str);
size_t strnlen (const char * str, size_t max);
int strcmp (const char * s1, const char * s2);
int strcasecmp (const char * s1, const char * s2);
int strncmp (const char * s1, const char * s2, size_t limit);
int strncasecmp (const char * s1, const char * s2, size_t limit);
char * strcat (char * s1, const char * s2);
char * strncat (char * s1, const char * s2, size_t limit);
char * strcpy (char * dest, const char * src);
char * strncpy (char * dest, const char * src, size_t limit);
char * strchr (const char * s, int c);
char * strrchr (const char * s, int c);
char * strpbrk (const char * s, const char * accept);
size_t strspn (const char * s, const char * accept);
size_t strcspn (const char * s, const char * reject);
char * strstr (const char * haystack, const char * needle);

#else

#define memcpy  __builtin_memcpy
#define memset  __builtin_memset
#define memcmp  __builtin_memcmp
#define strlen  __builtin_strlen
#define strnlen __builtin_strnlen
#define strcmp  __builtin_strcmp
#define strncmp __builtin_strncmp
#define strcat  __builtin_strcat
#define strncat __builtin_strncat
#define strstr  __builtin_strstr
#define strspn  __builtin_strspn
#define strcspn __builtin_strcspn
#define strchr  __builtin_strchr
#define strrchr __builtin_strrchr
#define strpbrk __builtin_strpbrk

#endif

int atoi (const char * buf);
int strtoi (const char * nptr, char ** endptr);
uint64_t atox (const char * buf);
uint64_t strtox (const char * nptr, char ** endptr);
void str_toupper (char * s);
void str_tolower (char * s);



#endif
