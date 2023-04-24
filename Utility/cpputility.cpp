#include "cpputility.h"



void string2hexString(unsigned char* input, char* output)
{
    int loop;
    int i; 
    
    i=0;
    loop=0;
    
    while(input[loop] != '\0')
    {
        sprintf((char*)(output+i),"%02X", input[loop]);
        loop+=1;
        i+=2;
    }
    //insert NULL at the end of the output string
    output[i++] = '\0';
}


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
        if (!isdigit(str.at(i)))
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

int is_empty_file(FILE *fp) 
{
    int c = getc(fp);
    if (c == EOF)
        return 1;
    ungetc(c, fp);
    return 0;
}

std::string generate_salt(int len)
{
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, charset.size() - 1);

    std::string salt;
    for (int i = 0; i < len; ++i) {
        salt += charset[distrib(gen)];
    }

    return salt;
}

void print_menu()
{
    printf("1. Add a password.\n");
    printf("2. Delete a password.\n");
    printf("3. Print all passwords.\n");
    printf("4. Reset master password.\n");
    printf("5. Exit.\n");
}
