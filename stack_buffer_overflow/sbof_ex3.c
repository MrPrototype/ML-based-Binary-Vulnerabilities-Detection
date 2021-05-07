#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
	char buff[512];
	if(argc < 2) {
		printf("Usage: %s <name>\n", argv[0]);
		exit(0);
	}
	strcpy(buff, argv[1]);
	printf("Your name: %s\n", buff);
	return 0;
}