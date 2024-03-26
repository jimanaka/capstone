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
  char input[500];
  printf("enter some values: ");
  fgets(input, 500, stdin);
  memcpy(buffer, input, strlen(input));
  buffer[4] = '\n';
  printf("your input was: %s\n", buffer);
  return EXIT_SUCCESS;
}
