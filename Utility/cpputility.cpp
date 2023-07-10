#include "cpputility.h"


unsigned char* hexStringToUnsignedChar(const std::string& hexString) 
{
    size_t size;
    size = hexString.length() / 2;  // Each byte is represented by 2 characters in a hex string
    unsigned char* result = new unsigned char[size];

    for (size_t i = 0; i < size; ++i) {
        unsigned int byteValue = 0;
        for (int j = 0; j < 2; ++j) {
            char c = hexString[i * 2 + j];

            // Convert hexadecimal character to integer value
            if (c >= '0' && c <= '9') {
                byteValue = (byteValue << 4) | (c - '0');
            }
            else if (c >= 'A' && c <= 'F') {
                byteValue = (byteValue << 4) | (c - 'A' + 10);
            }
            else if (c >= 'a' && c <= 'f') {
                byteValue = (byteValue << 4) | (c - 'a' + 10);
            }
        }

        result[i] = static_cast<unsigned char>(byteValue);
    }

    return result;
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

void cleanse(void* ptr, size_t len) {
  memset_func(ptr, 0, len);
}

void printCharArr(unsigned char* txt)
{
    for (int i = 0; ; i++) {
        if (txt[i] != NULL)
            printf("%02X ", txt[i]);
    }
    printf("\n");
}

void print_menu()
{
    printf("1. Add a password.\n");
    printf("2. Delete a password.\n");
    printf("3. Print all passwords.\n");
    printf("4. Reset master password (Deletes all passwords!).\n");
    printf("5. Exit.\n");
}
