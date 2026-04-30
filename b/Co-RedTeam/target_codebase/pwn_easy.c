#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

void win(void) {
    puts("FLAG{pwn_feasibility_success}");
}

int main(void) {
    struct {
        char buf[16];
        uint32_t guard;
    } frame = {{0}, 0};

    puts("send payload:");
    read(0, frame.buf, 64);
    if (frame.guard == 0x41424344) {
        win();
    } else {
        puts("nope");
    }
    return 0;
}
