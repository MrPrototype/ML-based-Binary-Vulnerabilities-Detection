#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	char buff[512], *envpoint;
	if((envpoint = (char *)getenv("TEST")) == NULL) {
		printf("No environmental variable TEST.\n");
		return 0;
	}
	strcpy(buff, envpoint);
	printf("The environmental variable TEST holds: %s\n", buff);
	return 0;
}