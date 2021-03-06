#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

/*Start declaration*/
void notSafeCopy(char* src);
void notSafeMerging(char* s);
void notSafeDifferentSizedStrings(char* s);
void notSafeMessageOverflow(char* s);
void concatenateOverStringStrcpy(char* s);
int validateBufferStrcpy(char* s);
void validateIndexOverflowArryStrcpy(int n, char* s);
void flushingAfterStrCpy(char* s);
void notSafeToCopy(char* s, int n);
void notSafeDynamicCopyStrncpy();
void notSafeDifferentSizeableStringStrncpy(char* s);
void notSafeDifferentSizedStringsStrncpy(char*s, int n);
void concatenateOverStringStrncpy(char* s);
void ignoreIndexOverflowArrysStrncpy();
void strncpysLimitedInput(int n);
void strncpyInputSplits();
void concatenateOverString(char* s, char* t); 
void ignoreBuffer(char* s);
void ignoreIndexOverflowArrys(char* s);
void notSafeCopyStrcat(char* s);
void notSafeDynamicCopyStrcat(char* s, int n);
void notSafeDifferentSizeableStringStrcat(char* s);
void notSafeMessageOverflowStrcat(char* s);
void inputStrCat(char* s);
void inputBuffer();
void issueMultipleScanfs();
void scanfInput();
void shortingSplittingScanf();
void notSafegetCopyScanf(int n);
void changeSizeStringScanf();
void overflowScanf();
void buffercopyScanf();
void smallSprintf(char* s);
void limitedSprintSprintf(char* s);
void flushingUnreadSprintf(char* s);
void tooLongStringSpritf();
void notSafeSprintf(char* s);
void notSafeSprintfMul(char* s, char* t);
void notSafegetSprintfTwo(int n);
void overflowSprintfWithArrayTwo(char* s);
void fgetsSmallBuffer();
void fgetsSmallBufferWithArg(char* s);
void fgetsConstantTooLong();
void fgetsWithDynamicSize();
char* fgetsWithReturnAndSmallArray();
int fgetsWithMalloc();
void fgetsPlaceInArray();
int fgetsThreeFgets();
void memcpySmallIntoLarge(char* s);
void memcpySafeFgets(char* s);
void memcpySmallBufferDynamic(char* s);
void memcpyWithArithmetic();
void memcpyWithArgs(int n);
void memcpyPlaceInArray();
void memcpyWithTwoArgs(int n, char* s);
void memcpyFunPointers(char* s);
int addTwo();
int mulTwo();
int divTwo();
void subTwo();
void benAritmetic();
void benRandAritmetic();
void mulArgWithI(int n);
void addUpNums();
void printString(char*s);
void printStringAndInt(char* s, int n);
void printStringWithLoop(char* s);
void printStringWithLoopAdd(char* s);
void printEcho();
void printEchoPuts();
void catFourStrings();
void prependString(char* t);
void shortPrint();
void shortIntDecl();
void shortIntDeclWithPrint();
void piRound();
void reversedString();
void roundFloat(float n);
void roundFloatWithArg(float n);
void calcAreaOfCircle();
void calcCircumference();
void printManyLines();
void fromAreaToRC(float n);
void mulTwoFloat();
int asciiOfChar();
void quotientAndRemainder();
void sizeOfVariables();
void swapNums();
void checkEven();
int checkVowel();
void findLargestNumber();
int checkLeapYear(int year);
void checkIfInAlphabet();
void calcNaturalNumbers();
void calcFactorial();
void showMulTable();
void printAtoZ();
void countDigits();
void countLetters(char* s);
void reverseNumber(int n);
void reversedStringArg(char* s);
void printHex();
void printOctal();
void avgOfThree(int n, int o, int t);
void avgOfThreeInput();
void printLastChar(char* s);
void printCharNum(char* s);
void hexToDecimal();
void lengthOfString();
void lengthOfStringArg(char* s);
void lengthOfTwoString(char* s, char* t);
void printPyr();
void concateTwoStrings();
void concatHard();
void printEvenNums();
void printOddNumbers();
void GCDinput();
void GCDarg(int n1, int n2);
void isNumberLargerThanTen(int n);
void isNumberLargerThanTenInput();
/*End declaration*/

int main(int argc, char* argv[]){
	/*Call start*/
    notSafeCopy(argv[1]);
    notSafeMerging(argv[1]);
    notSafeDifferentSizedStrings(argv[1]);
	notSafeMessageOverflow(argv[1]);
    concatenateOverStringStrcpy(argv[1]);
    validateBufferStrcpy(argv[1]);
	validateIndexOverflowArryStrcpy(strtol(argv[1], NULL, 10), argv[2]);
	flushingAfterStrCpy(argv[1]);
	notSafeToCopy(argv[1], strtol(argv[2], NULL, 10));
	notSafeDynamicCopyStrncpy();
	notSafeDifferentSizeableStringStrncpy(argv[1]);
	notSafeDifferentSizedStringsStrncpy(argv[1], strtol(argv[2], NULL, 10));
	concatenateOverStringStrncpy(argv[1]);
	ignoreIndexOverflowArrysStrncpy();
	strncpysLimitedInput(strtol(argv[1], NULL, 10));
	strncpyInputSplits();
	concatenateOverString(argv[1], argv[2]); 
	ignoreBuffer(argv[1]);
	ignoreIndexOverflowArrys(argv[1]);
	notSafeCopyStrcat(argv[1]);
	notSafeDynamicCopyStrcat(argv[1], strtol(argv[2], NULL, 10));
	notSafeDifferentSizeableStringStrcat(argv[1]);
	notSafeMessageOverflowStrcat(argv[1]);
    inputStrCat(argv[1]);
	inputBuffer();
	issueMultipleScanfs();
	scanfInput();
	shortingSplittingScanf();
	notSafegetCopyScanf(strtol(argv[1], NULL, 10));
	changeSizeStringScanf();
	overflowScanf();
	buffercopyScanf();
	smallSprintf(argv[1]);
	limitedSprintSprintf(argv[1]);
	flushingUnreadSprintf(argv[1]);
	tooLongStringSpritf();
	notSafeSprintf(argv[1]);
	notSafeSprintfMul(argv[1], argv[2]);
	notSafegetSprintfTwo(strtol(argv[1], NULL, 10));
	overflowSprintfWithArrayTwo(argv[1]);
	fgetsSmallBuffer();
	fgetsSmallBufferWithArg(argv[1]);
	fgetsConstantTooLong();
	fgetsWithDynamicSize();
    fgetsWithReturnAndSmallArray();
	fgetsWithMalloc();
	fgetsPlaceInArray();
	fgetsThreeFgets();
	memcpySmallIntoLarge(argv[1]);
	memcpySafeFgets(argv[1]);
	memcpySmallBufferDynamic(argv[1]);
	memcpyWithArithmetic();
	memcpyWithArgs(strtol(argv[1], NULL, 10));
	memcpyPlaceInArray();
	memcpyWithTwoArgs(strtol(argv[1], NULL, 10), argv[2]);
	memcpyFunPointers(argv[1]);
	addTwo();
	mulTwo();
	divTwo();
	subTwo();
	benAritmetic();
	benRandAritmetic();
	mulArgWithI(strtol(argv[1], NULL, 10));
	addUpNums();
	printString(argv[1]);
	printStringAndInt(argv[1], strtol(argv[2], NULL, 10));
	printStringWithLoop(argv[1]);
	printStringWithLoopAdd(argv[1]);
	printEcho();
	printEchoPuts();
	catFourStrings();
	prependString(argv[1]);
	shortPrint();
	shortIntDecl();
	shortIntDeclWithPrint();
	piRound();
	reversedString();
	roundFloat(atof(argv[1]));
	roundFloatWithArg(atof(argv[1]));
	calcAreaOfCircle();
	calcCircumference();
	printManyLines();
	fromAreaToRC(atof(argv[1]));
	mulTwoFloat();
	asciiOfChar();
	quotientAndRemainder();
	sizeOfVariables();
	swapNums();
	checkEven();
	checkVowel();
	findLargestNumber();
	checkLeapYear(strtol(argv[1], NULL, 10));
	checkIfInAlphabet();
	calcNaturalNumbers();
	calcFactorial();
	showMulTable();
	printAtoZ();
	countDigits();
	countLetters(argv[1]);
	reverseNumber(strtol(argv[1], NULL, 10));
	reversedStringArg(argv[1]);
	printHex();
	printOctal();
	avgOfThree(strtol(argv[1], NULL, 10), strtol(argv[2], NULL, 10), strtol(argv[3], NULL, 10));
	avgOfThreeInput();
	printLastChar(argv[1]);
	printCharNum(argv[1]);
	hexToDecimal();
	lengthOfString();
	lengthOfStringArg(argv[1]);
	lengthOfTwoString(argv[1], argv[2]);
	printPyr();
	concateTwoStrings();
	concatHard();
	printEvenNums();
	printOddNumbers();
	GCDinput();
	GCDarg(strtol(argv[1], NULL, 10), strtol(argv[2], NULL, 10));
	isNumberLargerThanTen(strtol(argv[1], NULL, 10));
	isNumberLargerThanTenInput();
	/*Call end*/
	return 0;
}
/*funcstart*/
void notSafeCopy(char* src){
	char dest[14];
    if(strlen(src) > sizeof(dest)){
        char longer[strlen(src)];
        strcpy(longer, src);
	    printf("Copied string: %s\n", longer);
    }else{
	    strcpy(dest, src);
	    printf("Copied string: %s\n", dest);
    }
}
/*funcend*/
/*funcstart*/
void notSafeMerging(char* s){
	char dest[15] = "Testing second";
	printf("Before: %s", dest);
    if(strlen(s) > sizeof(dest)){
        char longer[strlen(s)];
        strcpy(longer, s);
	    printf("After: %s\n", longer);
    }else{
	    strcpy(dest, s);
	    printf("After: %s\n", dest);
    }
}
/*funcend*/
/*funcstart*/
void notSafeDifferentSizedStrings(char* s){
	char src[40];
	char dest[strlen(s)];
	memset(dest, '\0', sizeof(dest));
	strcpy(src, "This is somesiteilike.com");
	strcpy(dest, src);
	strcpy(dest, s);
	printf("Final copied string : %s\n", dest);
}
/*funcend*/
/*funcstart*/
void notSafeMessageOverflow(char* s){
	char example[strlen(s)];
	memset(example, '\0', sizeof(example));
	strcpy(example, s);
	printf("%s\n", example);
}
/*funcend*
/*funcstart*/
void concatenateOverStringStrcpy(char* s){
	char* str1;
	char* str2;
	str1 = strdup("String");
    str2 = strdup("test");
    printf("%s\n", str1);
    printf("%s\n", str2);
	char dest[strlen(s)];
	strcpy(dest, s);
}
/*funcend*/
/*funcstart*/
int validateBufferStrcpy(char* s) {
	char buf[80];
	strcpy(buf, "s: ");
	if (strlen(s) < 81){
		strcpy(buf, s);
        printf("%s\n",buf);
        return 0;
    }
    return 0;
}
/*funcend*/
/*funcstart*/
void validateIndexOverflowArryStrcpy(int n, char* s){
    if(n < strlen(s)){
        n = strlen(s);
    }
	char dest[n];
	strcpy(dest, s);
	printf("dest : %s\n", dest);
}
/*funcend*/
/*funcstart*/
void flushingAfterStrCpy(char* s){
   	int t;
	srand((unsigned) time(&t));
	int a = rand()%50;
	int b = rand()%50;
	int c = rand()%50;
	printf("%d, %d, %d\n",a,b,c);
    if(a < strlen(s)){
        a = strlen(s);
    }
	char dest[a];
	strcpy(dest, s);
	printf("%s\n", s);
}
/*funcend*/
/*funcstart*/
void notSafeToCopy(char*s, int n){
	if(n<strlen(s)){
		n = strlen(s);
		char dest[n];
		strncpy(dest, s, strlen(s));
		printf("Copied string: %s\n", dest);
	}else{
		char dest[n];
		strncpy(dest, s, strlen(s));
		printf("Copied string: %s\n", dest);
	}
}
/*funcend*/
/*funcstart*/
void notSafeDynamicCopyStrncpy(){
	int n; 
	char tmp[256];
	printf("Enter size of string:\n");
	scanf("%d", &n);
    if(n<256){
        n = 256;
    }
	char dest[n];
	while((n= getchar()) != '\n' && n != EOF);
	printf("Enter string to store:\n");
	fgets(tmp, 256, stdin);
	strncpy(dest, tmp, strlen(tmp));
	printf("Final %s\n",dest);
}
/*funcend*/
/*funcstart*/
void notSafeDifferentSizeableStringStrncpy(char*s ){
	char* greeting = "Hello mr/ms:       ";
	char fin[strlen(s)+strlen(greeting)];
	strcat(fin, greeting);
	strncpy(&fin[strlen(greeting)],s,strlen(s));
	printf("%s\n", fin);
}
/*funcend*/
/*funcstart*/
void notSafeDifferentSizedStringsStrncpy(char* s, int n){
	int x, y, z;
	x = n+n;
	y = n-n;
	z = n*n;
	char dest[n];
	strncpy(dest, s, n);
	printf("Copied string: %s\n", dest);
}
/*funcend*/
/*funcstart*/
void concatenateOverStringStrncpy(char* s){
	char tmp[strlen(s)];
	char dest[50];
	printf("%d vs %d\n", sizeof(tmp), sizeof(dest));
	strncpy(tmp, s, strlen(s));
	tmp[0] = 'A';
	tmp[1] = 'B';
	tmp[2] = 'C';
	if(sizeof(tmp)>sizeof(dest)){
		printf("Copied string: %s\n", tmp);

	}else{
		strncpy(dest, tmp, strlen(s));
		printf("Copied string: %s\n", dest);
	}
}
/*funcend*/
/*funcstart*/
void ignoreIndexOverflowArrysStrncpy(){
	char sentence[10] = "";
	char *article[5] = { "the", "a", "one", "string", "any" };
	int t;
	srand((unsigned) time(&t));
	int a = rand()%5;
	strncpy(sentence, article[a], 10);
	printf("%s\n", sentence);
	fgets(sentence, sizeof(sentence), stdin);
}
/*funcend*/
/*funcstart*/
void strncpysLimitedInput(int n){
	char name[50];
	char name2[n];
	for (int i = 0; i <= 3; i++){
		printf("Enter any string? ");
		if (fgets(name, 50, stdin) != NULL)
			printf("Your string is: %s\n", name);
	}
	strncpy(name2, name, n);
    printf("%s\n",name2);
}
/*funcend*/
/*funcstart*/
void strncpyInputSplits(){
	int n = 0;
	char fin[5];
	printf("What is the size you want to allocate?\n");
	scanf("%d", &n);
	char buff[n];
	while((n= getchar()) != '\n' && n != EOF);
	printf("Enter the string you want to store:\n");
	fgets(buff, n, stdin);
	for(int i = 0; i < strlen(buff); i++){
		printf("%c", buff[i]);
	}
	printf("\n");
	if(n > sizeof(fin)){
		printf("final string %s\n", buff);
	}else{
		strncpy(fin, buff, strlen(buff));
		printf("final string %s\n", fin);
	}
}
/*funcend*/
/*funcstart*/
void concatenateOverString(char* s, char* t){
	char tmp[strlen(s)+strlen(t)];
	char dest[strlen(s)+strlen(t)];
	strcat(tmp, s);
	strcat(tmp,t);
	strcat(dest, tmp);
	printf("New String : %s\n",dest); 
}
/*funcend*/
/*funcstart*/
void ignoreBuffer(char* s) {
	char* greeting = "Hello mr./ms.:       ";
	char fin[strlen(s)+strlen(greeting)];
	strcat(fin, greeting);
	strcat(fin,s);
}
/*funcend*/
/*funcstart*/
void ignoreIndexOverflowArrys(char* s){
	char sentence[strlen(s)];
	char *article[5] = { "the", "a", "one", "some", "any" };
	int val = rand() % 4;
	strcat(sentence, article[val]);
	strcat(sentence, s);
}
/*funcend*/
/*funcstart*/
void notSafeCopyStrcat(char* s){
	char* src = "Testing input string, what happened:";
	int n = 4;
	int m = n*n;
	int x = m*m; 
	char dest[strlen(s)+ strlen(src)];
	strcat(dest, src);
	strcat(dest, s);
	printf("input string: %s\n", dest);
}
/*funcend*/
/*funcstart*/
void notSafeDynamicCopyStrcat(char* s, int n){
	int x = n*n;
	int y = n+n;
	int z = 2*n/3;
	char dest[strlen(s)];
	strcat(dest, s);
	printf("%s final \n",dest);
}
/*funcend*/
/*funcstart*/
void notSafeDifferentSizeableStringStrcat(char* s){
	char* first = "First";
	char* second = "Second";
	char* third = "Third";
	int n = strlen(third)*2;
	if(n < strlen(s)){
		n = strlen(s); 
	}
	char dest[strlen(first)+strlen(second)+n];
	strcat(dest, first);
	strcat(dest, second);
	strcat(dest, third);
	strcat(dest, s);
}
/*funcend*/
/*funcstart*/
void notSafeMessageOverflowStrcat(char* s){
	char example[strlen(s)+15];
	strcat(example, "Hello mr. ms: ");
	strcat(example, s);
}
/*funcend*/
/*funcstart*/
void inputStrCat(char *s){
	char tmp[20] = "This is a test String";
	char test [strlen(s)];
	for(int i = 0; i < strlen(test); i++){
		memset(&test[i], 'A', 1);
	}
	printf("%s\n", test);
	strcat(test,s); 
}
/*funcend*/
/*funcstart*/
void inputBuffer(){
	char str[100];
	scanf("%100s", str);
	printf("x = %d, str = %s\n", str, str);
}
/*funcend*/
/*funcstart*/
void issueMultipleScanfs(){
	int size;
	printf("Enter size of input ");
	scanf("%d", &size);
	char dest[size];
	snprintf(dest, sizeof(dest), "%%%ds", size - 1);
	printf("Enter string input ");
	scanf(dest, dest);
	printf("final: %s\n", dest);
}
/*funcend*/
/*funcstart*/
void scanfInput(){
	int a = 4;
	int b = 7;
	int c = a+b;
	printf("%d Total: \n",c);
	char buffer_input[10];
	scanf("%10s", buffer_input);
	printf("You entered: %s\n", buffer_input);
}
/*funcend*/
/*funcstart*/
void shortingSplittingScanf(){
	int x;
	char str[12] = "hello good day";
	int len = 10;
	scanf("%12s", str);
	for (x = 0; x <= len; x++){
		if (str[x] == '\n'){
			str[x] = '\0';
			break;
		}
	}
	printf("You entered: %s\n", str);
}
/*funcend*/
/*funcstart*/
void notSafegetCopyScanf(int n){
	printf("Your total size available: %d\n", n);
	char str1[n];
	snprintf(str1, sizeof(str1), "%%%ds", n - 1);
	scanf(str1, str1);
}
/*funcend*/
/*funcstart*/
void changeSizeStringScanf(){
	char src[40];
	char dest[100];
	memset(dest, '\0', sizeof(dest));
	scanf("%40s", src);
	strcpy(dest, src);
	printf("Final string : %s\n", dest);
}
/*funcend*/
/*funcstart*/
void overflowScanf(){
	int t;
	srand((unsigned) time(&t));
	int a = rand()%50;
	int b = rand()%70;
	int c = rand()%10;
	int d = a+b+c;
	int e = a-b-c;
	int f = a+b-c;
	char example[f];
	snprintf(example, sizeof(example), "%%%ds", f - 1);
	scanf(example, example);
	printf("%s\n", example);
}
/*funcend*/
/*funcstart*/
void buffercopyScanf(){
	char p[15];
	char* hw;
	int i;
	scanf("%15s", &p);
	hw = (p + 2);
	memcpy(hw, "abc" + 2, 5);
	printf("%s\n",hw);
}
/*funcend*/
/*funcstart*/
void smallSprintf(char* s){
	char buf[20];
    sprintf(buf,"You entered: %*.*s\n",0,sizeof(buf)-10,s);
    printf("%s\n",buf);
}
/*funcend*/
/*funcstart*/
void limitedSprintSprintf(char* s ){
	char number[5];
	int sum;
	printf("Enter any number\n");
	fgets(number, sizeof(number),stdin);
	sum = atoi(number);
	char dest[sum];
	char tmp[100];
	sprintf(tmp, "Final string %*.*s",0,sizeof(tmp)-10, s);
	printf("%s\n", tmp);
}
/*funcend*/
/*funcstart*/
void flushingUnreadSprintf(char* s){
	int t;
	srand((unsigned) time(&t));
	int a = rand()%50;
	int b = rand()%70;
	int c = rand()%10;
	int d = a+b+c;
	int e = a-b-c;
	int f = a+b-c;
	char dest[strlen(s)]; 
	sprintf(dest,"%s",s);
	printf("%s\n", dest);
}
/*funcend*/
/*funcstart*/
void tooLongStringSpritf(){
	char buf[20] = "Greetings mr. /ms:";
	char name[40];
	char dest[sizeof(buf)+ sizeof(name)+13]; 
	printf("Enter your name :\n");
	fgets(name,40,stdin );
	sprintf(dest,"final: %s %s",buf,  name);
	printf("%s\n", dest);
}
/*funcend*/
/*funcstart*/
void notSafeSprintf(char* s){
	char buf[20] = "Greetings mr. /ms:";
	char dest[strlen(s)]; 
	sprintf(dest,"final: %s %s",buf, s);
	printf("%s\n", dest);
}
/*funcend*/
/*funcstart*/
void notSafeSprintfMul(char* s, char* t){
	char final[strlen(s)+strlen(t)];
	char temp[strlen(s)+strlen(t)];
	strcat(temp, s);
	strcat(temp, t);
	sprintf(final, " str : %s", temp);
	printf("%s\n", final);
}
/*funcend*/
/*funcstart*/
void notSafegetSprintfTwo(int n){
	char buf[50];
	if(n>10){
		printf("Number greater than 10\n");
		fgets(buf, 50, stdin);
	}else{
		printf("Number less than or equal to 10\n");
		fgets(buf, 50, stdin);
	}
	if(n<50){
		n = 50;
	}
	char final[n];
	sprintf(final,"You entered : %s",buf);
	printf("%s\n", final);
}
/*funcend*/
/*funcstart*/
void overflowSprintfWithArrayTwo(char* s){
	char example[strlen(s)];
	example[0] = "A";
	example[1] = "B";
	example[2] = "C";
	sprintf(example,"%s\n", s);
	printf("final : %s\n", example);
}
/*funcend*/
/*funcstart*/
void fgetsSmallBuffer(){
    char str[2];
    fgets(str,sizeof(str),stdin);
    printf("%d and %s\n",sizeof(str), str);
}
/*funcend*/
/*funcstart*/
void fgetsSmallBufferWithArg(char* s){
    printf("Argument string: %s\n",s);
	char str[50];
	if(strlen(s)>sizeof(str)){
    	fgets(str, sizeof(str), stdin);
    	printf("Written string: %s\n",str);
	}else{
    	fgets(str, strlen(s), stdin);
    	printf("Written string: %s\n",str);
	}
}
/*funcend*/
/*funcstart*/
void fgetsConstantTooLong(){
    const int DATA_SIZE = 64;
    char buffer[DATA_SIZE];
    printf("Write your username: \n");
    fgets(buffer, DATA_SIZE, stdin);
    printf("Hello, %s",buffer);
}
/*funcend*/
/*funcstart*/
void fgetsWithDynamicSize(){
    int size; 
    printf("Enter size of input\n"); 
    scanf("%d",&size);
    char buffer[size];
    while((size= getchar()) != '\n' && size != EOF);
    fgets(buffer, size, stdin);
}
/*funcend*/
/*funcstart*/
char* fgetsWithReturnAndSmallArray(){
    char* inn[10];
    printf("%d\n",sizeof(int));
    fgets(inn,sizeof(char)*sizeof(inn),stdin);
    return inn; 
}
/*funcend*/
/*funcstart*/
int fgetsWithMalloc(){
    int size, width; 
    printf("Enter two numbers to add :\n");
    scanf("%d%d",&size, &width);
	printf("Total of the two :%d\n", size+width);
    while((size= getchar()) != '\n' && size != EOF);
    char string[50];
	printf("%d mul: \n", size*width);
    fgets(string, sizeof(string), stdin);
	printf("%s\n", string);
    return 0; 
}
/*funcend*/
/*funcstart*/
void fgetsPlaceInArray(){
    char test[20];
    printf("%ld\n", sizeof(test));
    memset(test, 'a', sizeof(test));
    printf("%s\n",test);
    fgets(test, 20, stdin);
	int pos = 15;
    fgets(&test[pos], sizeof(test)-pos, stdin);
    printf("%s\n",test);
}
/*funcend*/
/*funcstart*/
int fgetsThreeFgets(){
    int j = 10;
	int k = 10;
    int i = 0;
    scanf("%d",&i);
    char writes[k+j+i];
	while((i= getchar()) != '\n' && i != EOF);
	fgets(writes, i,stdin);
    fgets(writes, k,stdin);
    fgets(writes, j, stdin);
	return 0;
}
/*funcend*/
/*funcstart*/
void memcpySmallIntoLarge(char* s){
    char dest[256];
    memcpy(dest,s,sizeof(dest));
	printf("%s\n", dest);
}
/*funcend*/
/*funcstart*/
void memcpySafeFgets(char* s){
 	int size, width; 
    printf("Enter two numbers to add :\n");
    scanf("%d%d",&size, &width);
	printf("Total of the two :%d\n", size+width);
    while((size= getchar()) != '\n' && size != EOF);
    char tmp[50];
    memcpy(tmp, s, sizeof(tmp));
}
/*funcend*/
/*funcstart*/
void memcpySmallBufferDynamic(char* s){
    int size;
    scanf("%d",&size);
    char tmp[size];
    while((size= getchar()) != '\n' && size != EOF);
    fgets(tmp, sizeof(tmp), stdin);
    char dest[strlen(s)];
    memcpy(dest,s,strlen(s));
}
/*funcend*/
/*funcstart*/
void memcpyWithArithmetic(){
    int a = 4;
    int b = -5;
    int c = 2;
    int d = a+b+c;
    int e = a-b-c;
    int f = a/b*c;
    int g = a*b/c;
    int x = 35;
    printf("%d, %d, %d, %d\n", d, e, f, g);
    char bu[x];
    fgets(bu,sizeof(bu), stdin);
    char des[1];
    memcpy(des,bu,sizeof(des));
    printf("%s\n",des);
}
/*funcend*/
/*funcstart*/
void memcpyWithArgs(int n){
    char test[100];
    char fin[n];
    fgets(test, 100, stdin);
	if(n<sizeof(test)){
    	memcpy(fin,test,n);
	}else{
    	memcpy(fin,test,strlen(test));
	}
    printf("%s\n",fin);
}
/*funcend*/
/*funcstart*/
void memcpyPlaceInArray(){
    char test[20];
    char test2[40];
    char ex[40];
    printf("%ld\n", sizeof(test));
    fgets(test, 20, stdin);
    fgets(test2, 40, stdin);
    memcpy(ex, test2, sizeof(test2));
    printf("%s\n",ex);
}
/*funcend*/
/*funcstart*/
void memcpyWithTwoArgs(int n, char* s){
    char op[n];
	if(n<strlen(s)){
		char longer[strlen(s)];
    	memcpy(longer, s, strlen(s));
	}else{
    	memcpy(op, s, strlen(s));
	}
}
/*funcend*/
/*funcstart*/
void memcpyFunPointers(char* s){
  	int t;
	srand((unsigned) time(&t));
	int a = rand()%50;
	int b = rand()%50;
	int c = rand()%50;
	printf("%d, %d, %d\n",a,b,c);
	int x = a+b+c;
	if(x<strlen(s)){
		x = strlen(s);
	}
	char dest[x]; 
    strncpy(dest, s, strlen(s));
}
/*funcend*/
/*funcstart*/
int addTwo(){
	int x, y;
	printf("Write two numbers to add: \n");
	scanf("%d%d",&x,&y);
	printf("Added sum: %d\n", x+y);
    while((x= getchar()) != '\n' && x != EOF);
	return 0;
}
/*funcend*/
/*funcstart*/
int mulTwo(){
	int x, y;
	printf("Write two numbers to multiply: \n");
	scanf("%d%d",&x,&y);
	printf("Multiplied sum: %d\n", x*y);
    while((x= getchar()) != '\n' && x != EOF);
	return 0;
}
/*funcend*/
/*funcstart*/
int divTwo(){
	int x, y;
	printf("Write two numbers to divide: \n");
	scanf("%d%d",&x,&y);
	printf("First / second : %d\n", x/y);
    while((x= getchar()) != '\n' && x != EOF);
	return 0;
}
/*funcend*/
/*funcstart*/
void subTwo(){
	int x, y;
	printf("Write two numbers to subtract: \n");
	scanf("%d%d",&x,&y);
	printf("First - second : %d\n", x-y);
    while((x= getchar()) != '\n' && x != EOF);
}
/*funcend*/
/*funcstart*/
void benAritmetic(){
    int a = 4;
    int b = -5;
    int c = 2;
    int d = a+b+c;
    int e = a-b-c;
    int f = a/b*c;
    int g = a*b/c;
    int x = 35;
    printf("%d, %d, %d, %d\n", d, e, f, g);
}
/*funcend*/
/*funcstart*/
void benRandAritmetic(){
	int t;
	srand((unsigned) time(&t));
	int a = rand()%50;
	int b = rand()%70;
	int c = rand()%10;
	int d = a+b+c;
	int e = a-b-c;
	int f = a+b-c;
    printf("%d, %d, %d\n", d, e, f);
}
/*funcend*/
/*funcstart*/
void mulArgWithI(int n){
	int x;
	printf("Enter number you want to multiply with\n");
	scanf("%d",&x);
	printf("Input %d * %d = %d\n",n, x, n*x);
    while((x= getchar()) != '\n' && x != EOF);
}
/*funcend*/
/*funcstart*/
void addUpNums(){
	int answ = 0;
	int tmp; 
	for(int i = 0; i < 5; i++){
		printf("Start adding up numbers\n");
		scanf("%d", &tmp);
		answ += tmp;
		printf("Current total: %d\n", answ);
    	while((tmp= getchar()) != '\n' && tmp != EOF);
	}
}
/*funcend*/
/*funcstart*/
void printString(char* s){
	printf("Your string argument: %s\n", s);
}
/*funcend*/
/*funcstart*/
void printStringAndInt(char* s, int n){
	printf("Your string argument: %s\n", s);
	printf("Your number argument: %d\n", n);
}
/*funcend*/
/*funcstart*/
void printStringWithLoop(char* s){
	for(int i = 0; i < strlen(s); i++){
       	printf("%c",s[i]);
    }
    printf("\n");
}
/*funcend*/
/*funcstart*/
void printStringWithLoopAdd(char* s){
	int n = 10;
	int x = 20;
	int answ = n+x;
	for(int i = 0; i < strlen(s); i++){
       	printf("%c",s[i]);
    }
    printf("\n");
}
/*funcend*/
/*funcstart*/
void printEcho(){
    int n = 4;
    char dic[40];
    for(int i = 0; i < n; i++){
        printf("Write some strings, 40 letters only!\n");
        fgets(dic,40,stdin);
        printf("You wrote: %s\n", dic);
    }
}
/*funcend*/
/*funcstart*/
void printEchoPuts(){
    int n = 4;
    char dic[40];
	puts("hello");
	puts("theese ");
	puts("are ");
	puts("just");
	puts("strings");
    for(int i = 0; i < n; i++){
        printf("Write some strings, 40 letters only!\n");
        fgets(dic,40,stdin);
        printf("You wrote: %s\n", dic);
    }
}
/*funcend*/
/*funcstart*/
void catFourStrings(){
    int n = 4;
    char dic[40];
    for(int i = 0; i < n; i++){
        printf("Write some strings to concatenate!\n");
		char tmp[10];
		fgets(tmp, 10, stdin);
	    strcat(dic,tmp);
    }
     printf("Concatenated String %s\n", dic);
}
/*funcend*/
/*funcstart*/
void prependString(char* t){
	if(t){
		char s[strlen(t)];
		strncpy(s, t, strlen(t));
		s[0] = 'S';
		s[1] = 'T';
		s[2] = 'R';
		s[3] = 'I';
		s[4] = 'N';
		s[5] = 'G';
		s[6] = ':';
		printf("%s\n", s);
	}else{
		printf("No input\n");
	}
}
/*funcend*/
/*funcstart*/
void shortPrint(){
	printf("Hello!\n");
}
/*funcend*/
/*funcstart*/
void shortIntDecl(){
	int n = 4;
}
/*funcend*/
/*funcstart*/
void shortIntDeclWithPrint(){
	int n = 4;
	printf("%d\n", n);
}
/*funcend*/
/*funcstart*/
void piRound(){
	printf("%.5f\n", M_PI);
}
/*funcend*/
/*funcstart*/
void reversedString(){
	char s[5]= "HELLO";
	printf("%ld\n", strlen(s));
	for(int i = 1; i < sizeof(s)/2; i++){
		printf("%d : %ld\n", i, sizeof(s)-1-i);
		s[i] = s[sizeof(s)-i];
	}
	printf("Reveresed: %s\n", s);
}
/*funcend*/
/*funcstart*/
void roundFloat(float n){
	printf("New num %.5f\n", n);
}
/*funcend*/
/*funcstart*/
void roundFloatWithArg(float n){
	int x;
	printf("How many decimals?\n");
	scanf("%d",&x);
	printf("New num %.*f\n",x, n);
}
/*funcend*/
/*funcstart*/
void calcAreaOfCircle(){
	int x;
	printf("How large is radius?\n");
	scanf("%d",&x);
	printf("Area of circle is: %.4f\n",M_PI*(x*x));
}
/*funcend*/
/*funcstart*/
void calcCircumference(){
	int x;
	printf("How large is radius?\n");
	scanf("%d",&x);
	printf("Circumference of circle is: %.4f\n",(2*M_PI)*x);
}
/*funcend*/
/*funcstart*/
void printManyLines(){
	printf("Hello!\n");
	printf("How are you?\n");
	printf("I'am great!?\n");
	printf("Have a nice day?\n");
	printf("Goodbye!\n");
}
/*funcend*/
/*funcstart*/
void fromAreaToRC(float n){
	float r; 
	r = (n)/(2*M_PI);
	printf("Radius of circle with circuference %f:\n %f\n", n, r);
}
/*funcend*/
/*funcstart*/
void mulTwoFloat(){
    double a, b, product;
    printf("Enter two numbers: ");
    scanf("%lf %lf", &a, &b);  
    product = a * b;
    printf("Product = %.2lf", product);
}
/*funcend*/
/*funcstart*/
int asciiOfChar(){
	char c;
    printf("Enter a character: ");
    scanf("%c", &c);  
    printf("ASCII value of %c = %d", c, c);
    return 0;
}
/*funcend*/
/*funcstart*/
void quotientAndRemainder(){
    int dividend, divisor, quotient, remainder;
    printf("Enter dividend: ");
    scanf("%d", &dividend);
    printf("Enter divisor: ");
    scanf("%d", &divisor);
    quotient = dividend / divisor;
    remainder = dividend % divisor;
    printf("Quotient = %d\n", quotient);
    printf("Remainder = %d", remainder);
}
/*funcend*/
/*funcstart*/
void sizeOfVariables(){
	int intType;
    float floatType;
    double doubleType;
    char charType;
    printf("Size of int: %ld bytes\n", sizeof(intType));
    printf("Size of float: %ld bytes\n", sizeof(floatType));
    printf("Size of double: %ld bytes\n", sizeof(doubleType));
    printf("Size of char: %ld byte\n", sizeof(charType));
}
/*funcend*/
/*funcstart*/
void swapNums(){
	double first, second, temp;
    printf("Enter first number: ");
    scanf("%lf", &first);
    printf("Enter second number: ");
    scanf("%lf", &second);
    temp = first;
    first = second;
    second = temp;
    printf("\nAfter swapping, firstNumber = %.2lf\n", first);
    printf("After swapping, secondNumber = %.2lf\n", second);
}
/*funcend*/
/*funcstart*/
void checkEven(){
    int num;
    printf("Enter an integer: ");
    scanf("%d", &num);
    if(num % 2 == 0){
		printf("%d is even.\n", num);
	}else{
		printf("%d is odd.\n", num);
	}
}
/*funcend*/
/*funcstart*/
int checkVowel(){
    char c;
    int lowercase, uppercase;
    printf("Enter an alphabet: ");
    scanf("%c", &c);
    lowercase = (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u');
    uppercase = (c == 'A' || c == 'E' || c == 'I' || c == 'O' || c == 'U');
    if (lowercase || uppercase)
        printf("%c is a vowel.", c);
    else
        printf("%c is a consonant.", c);
}
/*funcend*/
/*funcstart*/
void findLargestNumber() {
    double n1, n2, n3;
    printf("Enter three numbers: ");
    scanf("%lf %lf %lf", &n1, &n2, &n3);
    if (n1 >= n2) {
        if (n1 >= n3)
            printf("%.2lf is the largest number.", n1);
        else
            printf("%.2lf is the largest number.", n3);
    } else {
        if (n2 >= n3)
            printf("%.2lf is the largest number.", n2);
        else
            printf("%.2lf is the largest number.", n3);
    }
}
/*funcend*/
/*funcstart*/
int checkLeapYear(int year) {
    if (year % 4 == 0) {
        if (year % 100 == 0) {
            if (year % 400 == 0)
                printf("%d is a leap year.\n", year);
            else
                printf("%d is not a leap year.\n", year);
        } else
            printf("%d is a leap year.\n", year);
    } else
        printf("%d is not a leap year.\n", year);
    return 0;
}
/*funcend*/
/*funcstart*/
void checkIfInAlphabet(){
    char c;
    printf("Enter a character: ");
    scanf("%c", &c);
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
        printf("%c is an alphabet.\n", c);
    else
        printf("%c is not an alphabet.\n", c);
}
/*funcend*/
/*funcstart*/
void calcNaturalNumbers(){
	int n, i, sum = 0;
    printf("Enter a positive integer: ");
    scanf("%d", &n);
    for (i = 1; i <= n; ++i) {
        sum += i;
    }
    printf("Sum = %d\n", sum);
}
/*funcend*/
/*funcstart*/
void calcFactorial(){
	int n, i;
    unsigned long long fact = 1;
    printf("Enter an integer: ");
    scanf("%d", &n);
    if (n < 0)
        printf("Error! Factorial of a negative number doesn't exist.\n");
    else {
        for (i = 1; i <= n; ++i) {
            fact *= i;
        }
        printf("Factorial of %d = %llu\n", n, fact);
    }
}
/*funcend*/
/*funcstart*/
void showMulTable(){
	int n, i;
    printf("Enter an integer: ");
    scanf("%d", &n);
    for (i = 1; i <= 10; ++i) {
        printf("%d * %d = %d \n", n, i, n * i);
    }
}
/*funcend*/
/*funcstart*/
void printAtoZ(){
    char c;
    for (c = 'A'; c <= 'Z'; ++c){
        printf("%c ", c);
	}
}
/*funcend*/
/*funcstart*/
void countDigits(){
    long long n;
    int count = 0;
    printf("Enter an integer: ");
    scanf("%lld", &n);
    while (n != 0) {
        n /= 10;     
        ++count;
    }
    printf("Number of digits: %d\n", count);
}
/*funcend*/
/*funcstart*/
void countLetters(char* s){
    printf("Number of characters: %d \n", strlen(s));
}
/*funcend*/
/*funcstart*/
void reverseNumber(int n) {
    int  rev = 0, remainder;
    while (n != 0) {
        remainder = n % 10;
        rev = rev * 10 + remainder;
        n /= 10;
    }
    printf("Reversed number = %d\n", rev);
    return 0;
}
/*funcend*/
/*funcstart*/
void reversedStringArg(char* s){
	char buff[strlen(s)];
	printf("%d\n", strlen(s));
	for(int i = 0; i < strlen(s); i++){
		buff[strlen(s)-i] = s[i];
	}
	printf("Original string: %s\n", s);
	printf("Reversed string: %s\n", buff);
}
/*funcend*/
/*funcstart*/
void printHex(){
	long long num; 
	printf("Write a decimal number to convert:\n");
	scanf("%lld", &num);
	printf("%d as hex: %x\n",num,  num);
}
/*funcend*/
/*funcstart*/
void printOctal(){
	long long num; 
	printf("Write a decimal number to convert:\n");
	scanf("%lld", &num);
	printf("%d as oct: %o\n",num,  num);
}
/*funcend*/
/*funcstart*/
void avgOfThree(int n, int o, int p){
	int total = n+o+p;
	int avg = total /3;
	printf("Average of [%d, %d, %d] : %d\n", n,o,p,avg);
}
/*funcend*/
/*funcstart*/
void avgOfThreeInput(){
	int total, n, o, p;
	printf("Write three numbers to average: \n");
	scanf("%d%d%d", &n,&o,&p);
	total = n+o+p;
	int avg = total /3;
	printf("Average of [%d, %d, %d] : %d\n", n,o,p,avg);
}
/*funcend*/
/*funcstart*/
void printLastChar(char* s){
	printf("Last character in string: %c\n",s[strlen(s)-1]);
}
/*funcend*/
/*funcstart*/
void printCharNum(char* s){
	int pos; 
	printf("Which character do you want?\n");
	scanf("%d", &pos);
	if(pos > strlen(s)-1){
		pos = strlen(s)-1;
	}
	printf("Character num %d in string: %c\n",pos, s[pos]);
}
/*funcend*/
/*funcstart*/
void hexToDecimal(){
	unsigned int value; 
	printf("Ender hexdecimal number: \n");
	scanf("%x", &value);
	printf("Hex %x as decimal: %d\n", value, value);
}
/*funcend*/
/*funcstart*/
void lengthOfString() {
    char s[] = "Programming is fun";
    int i;
    for (i = 0; s[i] != '\0'; ++i);
    printf("Length of the string: %d\n", i);
}
/*funcend*/
/*funcstart*/
void lengthOfStringArg(char* s) {
    int i;
    for (i = 0; s[i] != '\0'; ++i);
    printf("Length of the string: %d\n", i);
}
/*funcend*/
/*funcstart*/
void lengthOfTwoString(char* s, char* t){
	int i,  j;
    for (i = 0; s[i] != '\0'; ++i);
    for (j = 0; t[j] != '\0'; ++j);
    printf("Length both strings: %d\n", i+j);
}
/*funcend*/
/*funcstart*/
void printPyr(){
    int i, space, rows, k=0;
    printf("Enter number of rows: ");
    scanf("%d", &rows);
    for (i=1; i<=rows; ++i,k=0) {
        for (space=1; space<=rows-i; ++space)
        { printf("  "); }
        while (k!=2*i-1) {
            printf("* ");
            ++k;
        }
        printf("\n");
    }    
}
/*funcend*/
/*funcstart*/
void concateTwoStrings(){
	char* s = "Hello";
	char* split = " ";
	char* t ="Somethings";
	char dest[strlen(s)+strlen(t)+strlen(split)];
	strcat(dest, s);
	strcat(dest, split);
	strcat(dest, t);
	printf("Combined strings: %s\n", dest);
}
/*funcend*/
/*funcstart*/
void concatHard(){
	char s1[100] = "programming ", s2[] = "is awesome";
    int i, j;
    for (i = 0; s1[i] != '\0'; ++i);
    for (j = 0; s2[j] != '\0'; ++j, ++i) {
        s1[i] = s2[j];
    }
    s1[i] = '\0';
    printf("After concatenation: ");
    puts(s1);
}

/*funcend*/
/*funcstart*/
void printEvenNums(){
	long long upper; 
	printf("Enter number :\n");
	scanf("%lld", &upper);
	for(int i = 0;i<upper; i++ ){
		if(i % 2 == 0){
			printf("%d,",i);
		}
	}
}
/*funcend*/
/*funcstart*/
void printOddNumbers(){
	long long upper; 
	printf("Enter number :\n");
	scanf("%lld", &upper);
	for(int i = 0;i<upper; i++ ){
		if(i % 2 != 0){
			printf("%d,",i);
		}
	}
}
/*funcend*/
/*funcstart*/
void GCDinput(){
	int n1, n2, i, gcd;
    printf("Enter two integers: ");
    scanf("%d %d", &n1, &n2);
    for(i=1; i <= n1 && i <= n2; ++i)    {
        if(n1%i==0 && n2%i==0){
            gcd = i;
		}
    }
    printf("G.C.D of %d and %d is %d\n", n1, n2, gcd);
}
/*funcend*/
/*funcstart*/
void GCDarg(int n1, int n2){
	int i, gcd;
    for(i=1; i <= n1 && i <= n2; ++i)    {
        if(n1%i==0 && n2%i==0){
            gcd = i;
		}
    }
    printf("G.C.D of %d and %d is %d\n", n1, n2, gcd);
}
/*funcend*/
/*funcstart*/
void isNumberLargerThanTen(int n){
	if(n>10){
		printf("N is larger than 10!\n");
	}else{
		printf("N less than or equal to 10!\n");
	}
}
/*funcend*/
/*funcstart*/
void isNumberLargerThanTenInput(){
	int n;
	printf("Enter number: \n");
	scanf("%d", &n);
	if(n>10){
		printf("N is larger than 10!\n");
	}else{
		printf("N less than or equal to 10!\n");
	}
}
/*funcend*/