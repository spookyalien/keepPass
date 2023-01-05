#include "utility.h"


void printCharArr(unsigned char* arr, int len, bool asChar)
{
    char hex[16] = "0123456789ABCDEF";

    printf("{ ");
    for (int i = 0; i < len; i++) {
        printf("%c%c ", hex[arr[i] >> 4], hex[arr[i] & 0x0f]);
    }
    printf("}\n");
}

void reverse_arr(unsigned char* arr, int i, int f)
{
    //Reversing array by swapping at middle
    while (i < f) {
        unsigned char tmp = arr[i];
        arr[i] = arr[f];
        arr[f] = tmp;
        i++;
        f--;
    }
}

void left_rotate(unsigned char* arr, int d, int n)
{
    reverse_arr(arr, 0, d - 1);
    reverse_arr(arr, d, n - 1);
    reverse_arr(arr, 0, n - 1);
}

void right_rotate(unsigned char* arr, int d, int n)
{
    // right rotation of matrix is complement of left rotation
    left_rotate(arr, n - d, n); 
}


void random_char_arr(unsigned char* arr, int n)
{
    return;

}