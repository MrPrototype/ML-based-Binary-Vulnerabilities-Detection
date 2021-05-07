#include <stdio.h>
#include <string.h>

int main(int argc, const char **argv, const char **envp) {
	char giveflag[4];
	char word[264]; 
	int v6;

	v6 = 0;
	strcpy(giveflag, "No.");
	printf("What's your favorite word? ", argv, envp);
	scanf("%s", word);
	if ( !strcmp(giveflag, "Yesss!") )
		printf("Flag is: spbctf{*********************}\n", "Yesss!");
	else
		printf("Good, but i won't give you flag.\n", "Yesss!");
	return v6;
}