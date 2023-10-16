#include <stdio.h>
#include <stdlib.h>

int test(int * x, int y) {
	
	*x = *x * 2;
	y = y + 4;

	return *x + y;

}

int main() {
	
	int y = 4;

	int x = test(&y, 8);
	printf("%d\n", x);
	return 0;
}
