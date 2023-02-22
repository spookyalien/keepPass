#include "cpputility.h"

void printCharArr(unsigned char* arr, int len)
{
    const char hex[17] = "0123456789ABCDEF";

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


unsigned int stoi_with_check(const std::string& str) // if numeric -> convert string to int, if not numeric -> return 0
{
    bool is_numeric = true;
    for (unsigned int i = 0; i < str.length(); ++i)
    {
        if (not isdigit(str.at(i)))
        {
            is_numeric = false;
            break;
        }
    }
    if (is_numeric)
    {
        return stoi(str);
    }
    else
    {
        return 0;
    }
}

void print_menu()
{
    printf("1. Add a password.\n");
    printf("2. Delete a password.\n");
    printf("3. Print all passwords.\n");
    printf("4. Exit.\n");
}
