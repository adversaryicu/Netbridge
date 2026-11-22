/* Session lease only: stdin EOF or 15 seconds without data ends the service.
 * systemd ExecStopPost owns all networking cleanup, including SIGKILL cases.
 */
#include <errno.h>
#include <poll.h>
#include <unistd.h>

int main(void) {
    struct pollfd input = { .fd = STDIN_FILENO, .events = POLLIN };
    char buffer[256];
    for (;;) {
        int result = poll(&input, 1, 15000);
        if (result == 0) return 0;
        if (result < 0) {
            if (errno == EINTR) continue;
            return 1;
        }
        if (input.revents & POLLIN) {
            if (read(STDIN_FILENO, buffer, sizeof buffer) <= 0) return 0;
        } else if (input.revents & (POLLHUP | POLLERR | POLLNVAL)) {
            return 0;
        }
    }
}
