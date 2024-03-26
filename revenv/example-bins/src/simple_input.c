#include <stdio.h>

int main() {
    char input[100]; // Assuming a maximum input length of 100 characters

    // Prompt the user for input
    printf("Enter your input: ");
    
    // Read user input
    fgets(input, sizeof(input), stdin);

    // Print the input back to the user
    printf("You entered: %s\n", input);

    return 0;
}
