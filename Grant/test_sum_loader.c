// test_sum_loader.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <string.h>

// IOCTL commands (must match those in the kernel module)
#define WASM_IOC_MAGIC 'w'
#define WASM_IOC_SET_DATA _IOW(WASM_IOC_MAGIC, 1, struct wasm_data)
#define WASM_IOC_PROCESS_SUM _IO(WASM_IOC_MAGIC, 0)
#define WASM_IOC_PROCESS_TEST _IO(WASM_IOC_MAGIC, 1)

struct wasm_data {
    uint32_t size;
    int32_t array[10]; // Adjust the size as needed
};

// Function to display usage
void usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s <wasm_file> sum\n", prog_name);
    fprintf(stderr, "Example: %s wasm/sum_prog.wasm sum\n", prog_name);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return 1;
    }

    const char *wasm_file = argv[1];
    const char *process_type = argv[2];

    // Validate process type
    if (strcmp(process_type, "sum") != 0) {
        fprintf(stderr, "Invalid process type: %s\n", process_type);
        usage(argv[0]);
        return 1;
    }

    // Determine IOCTL command based on process type
    unsigned int ioctl_cmd;
    if (strcmp(process_type, "sum") == 0) {
        ioctl_cmd = WASM_IOC_PROCESS_SUM;
    } else if (strcmp(process_type, "test") == 0) {
        ioctl_cmd = WASM_IOC_PROCESS_TEST;
    } else {
        fprintf(stderr, "Invalid process type: %s\n", process_type);
        usage(argv[0]);
        return 1;
    }

    // Step 1: Read the WASM file
    FILE *f = fopen(wasm_file, "rb");
    if (!f) {
        perror("Failed to open WASM file");
        return 1;
    }

    // Get file size
    struct stat st;
    if (stat(wasm_file, &st) != 0) {
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

    // Step 2: Open the character device
    int fd = open("/dev/wasm_device", O_RDWR);
    if (fd < 0) {
        perror("Failed to open /dev/wasm_device");
        free(buffer);
        return 1;
    }

    // Step 3: Write the WASM code to the kernel module
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

    // Step 4: Send additional data (array values)
    struct wasm_data data;
    data.size = 10;
    for (uint32_t i = 0; i < data.size; i++) {
        data.array[i] = i * 10; // Example data values: 0, 10, 20, ..., 90
    }

    // Use ioctl to send data to the kernel module
    if (ioctl(fd, WASM_IOC_SET_DATA, &data) < 0) {
        perror("ioctl SET_DATA failed");
        close(fd);
        free(buffer);
        return 1;
    }
    printf("Data sent to kernel module successfully\n");

    // Step 5: Trigger execution of the WASM code in kernel space
    if (ioctl(fd, ioctl_cmd) < 0) {
        perror("ioctl PROCESS failed");
        close(fd);
        free(buffer);
        return 1;
    }
    printf("WASM code processed successfully via ioctl\n");

    // Step 6: Clean up
    close(fd);
    free(buffer);
    return 0;
}
