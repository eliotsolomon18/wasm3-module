#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#define DEVICE_NAME "/dev/wasm_prog_load"
#define IOCTL_SEND_BYTES_WITH_SIZE _IOW('a', 2, struct wasm_data)

struct wasm_data {
    char *data;
    size_t size;
    char* hook_cmd; // currently redundant but may need in future
};

struct wasm_data wdata;
char* data;

/**
 * This should be part of a library for ease of use by the user.
 */
int fetch_wasm_binary(const char* file_path) {
    int fd;
    struct stat st;
    
    // Get the size of the file
    if (stat(file_path, &st) != 0) {
        perror("Failed to get file size");
        return 1;
    }
    size_t file_size = st.st_size;
    wdata.size = file_size;

    // Allocate memory for the file content
    char* data = malloc(file_size);
    if (data == NULL) {
        perror("Failed to allocate memory");
        return 1;
    }

    // Open the file
    int file_fd = open(file_path, O_RDONLY);
    if (file_fd < 0) {
        perror("Failed to open file");
        free(data);
        return 1;
    }

    // Read the file content
    ssize_t read_ret = read(file_fd, data, file_size);
    if (read_ret < 0) {
        perror("Failed to read file");
        close(file_fd);
        free(data);
        return 1;
    }

    wdata.data = data;

    close(file_fd);

    return 0;
}

/**
 * This is what the user should typically write in their program.
 */
int main() {
    int fd;
    

    // Loads binary into char* data
    int fetch_ret = fetch_wasm_binary("wasm/prog.wasm");
    if (fetch_ret != 0) {
        return 1;
    }

    wdata.hook_cmd = "nf_drop_packet";

    fd = open(DEVICE_NAME, O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }

    if (ioctl(fd, IOCTL_SEND_BYTES_WITH_SIZE, &wdata) < 0) {
        perror("Failed to send bytes");
        close(fd);
        return 1;
    }

    printf("Bytes sent to kernel\n");
    close(fd);
    return 0;
}