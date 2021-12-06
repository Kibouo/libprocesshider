#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>

// NOTE: `/proc/<pid>` will still be accessible. However, unlike remounting `/proc` with `hidepid`, this will hide processes even from root.

// should be in `linux/limits.h` but compiler doesn't seem to find it for some reason
#define ARG_MAX       131072	/* # bytes of args + environ for exec() */

/*
 * Every process which includes this string in its cmdline will be filtered
 */
static const char* str_to_filter = "alacritty";

/*
 * Get a directory name given a DIR* handle
 */
static int get_dir_name(DIR* dirp, char* buf, size_t size)
{
    int fd = dirfd(dirp);
    if(fd == -1) {
        return 0;
    }

    char tmp[size];
    snprintf(tmp, size, "/proc/self/fd/%d", fd);
    ssize_t ret = readlink(tmp, buf, size);
    if(ret == -1) {
        return 0;
    }

    buf[ret] = 0;
    return 1;
}

/*
 * Get a process cmdline given its pid
 */
static int get_cmdline(char* pid, char* buf, size_t size)
{
    if(strspn(pid, "0123456789") != strlen(pid)) {
        return 0;
    }

    char tmp[size];
    snprintf(tmp, size, "/proc/%s/cmdline", pid);

    FILE* f = fopen(tmp, "r");
    if(f == NULL) {
        return 0;
    }

    if(fgets(buf, size, f) == NULL) {
        fclose(f);
        return 0;
    }
    fclose(f);

    return 1;
}

// the `\` are needed for original_##readdir to be interpretted properly apparently?
#define DECLARE_READDIR(dirent, readdir)                                \
static struct dirent* (*original_##readdir)(DIR*) = NULL;               \
                                                                        \
struct dirent* readdir(DIR *dirp)                                       \
{                                                                       \
    if(original_##readdir == NULL) {                                    \
        original_##readdir = dlsym(RTLD_NEXT, #readdir);                \
        if(original_##readdir == NULL)                                  \
        {                                                               \
            fprintf(stderr, "Error in dlsym: %s\n", dlerror());         \
        }                                                               \
    }                                                                   \
                                                                        \
    struct dirent* dir;                                                 \
                                                                        \
    while(1)                                                            \
    {                                                                   \
        dir = original_##readdir(dirp);                                 \
        if(dir) {                                                       \
            char dir_name[PATH_MAX];                                    \
            char cmdline[ARG_MAX + NAME_MAX + PATH_MAX];                \
            if(get_dir_name(dirp, dir_name, sizeof(dir_name)) &&        \
                strcmp(dir_name, "/proc") == 0 &&                       \
                get_cmdline(dir->d_name, cmdline, sizeof(cmdline)) &&   \
                strstr(cmdline, str_to_filter) != 0) {                  \
                continue;                                               \
            }                                                           \
        }                                                               \
        break;                                                          \
    }                                                                   \
    return dir;                                                         \
}

DECLARE_READDIR(dirent64, readdir64);
DECLARE_READDIR(dirent, readdir);
