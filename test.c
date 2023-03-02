#include <stdio.h>

int main() {
    char buffer[8];
    printf("Enter some text: ");
    gets(buffer);
    printf("You entered: %s\n", buffer);
    return 0;
}
