// sudo dnf install systemtap-sdt-devel
#include <sys/sdt.h>
#include <sys/time.h>
#include <unistd.h>

int main() {
    struct timeval tv;
    while(1) {
        gettimeofday(&tv, NULL);
        DTRACE_PROBE1("hello-usdt", "probe-main", tv.tv_sec);
        sleep(1);
    }
    return 0;
}
