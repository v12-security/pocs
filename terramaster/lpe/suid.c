#include <unistd.h>
int main(int argc, char **argv) {
    setuid(0);
    setgid(0);
    if (argc > 1)
        execvp(argv[1], argv + 1);
    else
        execl("/bin/sh", "sh", NULL);
}
