#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void hexdump(const unsigned char *buffer, size_t length)
{
	for (size_t i = 0; i < length; i++) {
		if ((i % 16) == 0)
			printf("%08x  ", (unsigned int) i);

		printf("%02x ", buffer[i]);

		if (((i % 16) == 15) || (i == (length - 1))) {
			if ((i % 16) < 8)
				printf(" ");

			for (size_t j = (i % 16); j < 15; j++)
				printf("   ");
			printf("|");

			for (size_t j = (i - (i % 16)); j <= i; j++) {
				char c = buffer[j];

				if ((c > 31) && (c < 127))
					printf("%c", c);
				else
					printf(".");
			}
			printf("|\n");
		} else if ((i % 8) == 7) {
			printf(" ");
		}
	}
}

int main(int argc, char **argv)
{
	void (*sc)(void);
	struct stat filestat;
	void *ptr;
	int fd;

	if (argc != 2) {
		printf("Usage: %s <file shellcode>\n", argv[0]);
		return -1;
	}

	printf("[+] shellcode file: %s\n", argv[1]);

	if ((fd = open(argv[1], O_RDONLY)) == -1) {
		perror("[!] open() failed");
		return -1;
	}

	if (fstat(fd, &filestat) != 0) {
		perror("[!] stat() failed");
		return -1;
	}

	printf("[+] size of file: %ld bytes\n", filestat.st_size);

	ptr = mmap(NULL, filestat.st_size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

	if (ptr == MAP_FAILED) {
		perror("[!] mmap failed");
		exit(1);
	}

	if (read(fd, ptr, filestat.st_size) != filestat.st_size) {
		fprintf(stderr, "[!] read() returned unexpected length of data.\n");
		exit(1);
	}

	if (close(fd) != 0) {
		perror("[!] error in close(fd)");
	}

	sc = (void (*)()) ptr;

	printf("[+] hexdump of shellcode:\n");
	hexdump(ptr, filestat.st_size);

	printf("[+] entering shellcode:\n");

	sc();

	printf("[+] shellcode returned.\n");

	memset(ptr, 0, filestat.st_size);
	if (munmap(ptr, filestat.st_size) != 0) {
		perror("[!] munmap() failed");
		return -1;
	}

	return 0;
}
