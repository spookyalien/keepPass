#include "utility.h"

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
    std::cout << "1. Add a password.\n";
    std::cout << "2. Delete a password.\n";
    std::cout << "3. Print all passwords.\n";
    std::cout << "4. Exit.\n";
}
