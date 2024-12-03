// test_loader.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>  // Include stdint.h for uint8_t
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#define WASM_IOC_MAGIC 'w'
#define WASM_IOC_PROCESS _IO(WASM_IOC_MAGIC, 0)

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <wasm_file>\n", argv[0]);
        return 1;
    }

    // Open the WASM file
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("Failed to open WASM file");
        return 1;
    }

    // Get file size
    struct stat st;
    if (stat(argv[1], &st) != 0) {
        perror("Failed to get file size");
        fclose(f);
        return 1;
    }
    size_t size = st.st_size;

    // Read the WASM code into a buffer
    uint8_t *buffer = malloc(size);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate memory\n");
        fclose(f);
        return 1;
    }

    if (fread(buffer, 1, size, f) != size) {
        fprintf(stderr, "Failed to read WASM file\n");
        free(buffer);
        fclose(f);
        return 1;
    }
    fclose(f);

    // Open the character device
    int fd = open("/dev/wasm_device", O_RDWR);
    if (fd < 0) {
        perror("Failed to open /dev/wasm_device");
        free(buffer);
        return 1;
    }

    // Write the WASM code to the device
    ssize_t write_ret = write(fd, buffer, size);
    if (write_ret < 0) {
        perror("Failed to write to device");
        close(fd);
        free(buffer);
        return 1;
    } else if ((size_t)write_ret != size) {
        fprintf(stderr, "Incomplete write to device\n");
        close(fd);
        free(buffer);
        return 1;
    }
    printf("WASM code loaded into kernel module successfully\n");

    // Use ioctl to trigger processing of the WASM code
    int ioctl_ret = ioctl(fd, WASM_IOC_PROCESS);
    if (ioctl_ret < 0) {
        perror("ioctl failed");
        close(fd);
        free(buffer);
        return 1;
    }
    printf("WASM code processed successfully via ioctl\n");

    // Close the device file
    close(fd);

    free(buffer);
    return 0;
}
