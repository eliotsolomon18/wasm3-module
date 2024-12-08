#include <sys/stat.h>

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#define DEVICE_PATH "/dev/wasm"

int
main(int argc, char *argv[])
{
    // Check that the correct number of arguments were passed in.
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file_path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Open the file to read its contents.
    const char *file_path = argv[1];
    int file_fd = open(file_path, O_RDONLY);
    if (file_fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }

    // Get the file size.
    struct stat file_stat;
    if (fstat(file_fd, &file_stat) < 0) {
        perror("fstat");
        close(file_fd);
        return EXIT_FAILURE;
    }
    ssize_t file_size = file_stat.st_size;

    // Allocate a buffer to temporarily store the file contents.
    char *buffer = (char *)malloc(file_size);
    if (!buffer) {
        perror("malloc");
        close(file_fd);
        return EXIT_FAILURE;
    }

    // Read the file contents into a buffer.
    if (read(file_fd, buffer, file_size) != file_size) {
        perror("read");
        free(buffer);
        close(file_fd);
        return EXIT_FAILURE;
    }

    // Close the file.
    close(file_fd);

    // Open the character device for writing.
    int dev_fd = open(DEVICE_PATH, O_WRONLY);
    if (dev_fd < 0) {
        perror("open");
        free(buffer);
        return EXIT_FAILURE;
    }

    // Write the file contents to the device.
    if (write(dev_fd, buffer, file_size) != file_size) {
        perror("write");
        free(buffer);
        close(dev_fd);
        return EXIT_FAILURE;
    }

    printf("Successfully wrote %zu bytes to %s\n", file_size, DEVICE_PATH);

    // Clean up.
    free(buffer);
    close(dev_fd);

    return EXIT_SUCCESS;
}