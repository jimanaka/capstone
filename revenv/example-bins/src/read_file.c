#include <stdio.h>

int main() {
    FILE *file;
    char ch;

    // Open the file in read mode
    file = fopen("test.txt", "r");

    // Check if file opened successfully
    if (file == NULL) {
        printf("Error opening file!\n");
        return 1;
    }

    // Read and print contents character by character
    while ((ch = fgetc(file)) != EOF) {
        printf("%c", ch);
    }

    // Close the file
    fclose(file);

    return 0;
}
