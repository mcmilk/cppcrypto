#ifndef CRYPTOR_COMPATIBILITY_H
#define CRYPTOR_COMPATIBILITY_H

// Windows needs wide API to support Unicode file names, while other platforms are assumed to support UTF-8 in narrow strings.
// We use wide API in the cryptor code and add dirty defines here to make the app compilable on all target platforms.

#ifndef _MSC_VER
#define wchar_t char
#define _T(A) A
#define _stat64 stat
#define _wstat64 stat
#define _wremove remove
#define _wrename rename
#define wstring string
#define wmain main
#define wregex regex
#define wsmatch smatch
#define wcerr cerr
#define wcout cout
#define wifstream ifstream
#define wprintf printf
#define wsprintf sprintf
#define sscanf_s sscanf
#define wostringstream ostringstream
#else
#define _T(A) L ## A
#endif

#endif

