#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

void win() {
  printf("you win!\n");
};

int main(int argc, char *argv[])
{
  char buffer[5];
  char input[50];
  printf("enter some values: ");
  fgets(input, 50, stdin);
  memcpy(buffer, input, 50);
  printf("your input was: %s\n", buffer);
  return EXIT_SUCCESS;
}
