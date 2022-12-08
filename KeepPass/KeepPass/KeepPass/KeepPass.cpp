#include <iostream>
#include <string>
#include "utility.h"
#include "PassClass.h"

void launch()
{
    KeepPass pass;
    std::string user_input = "";
    std::cout << "--------------------------------\n";
    std::cout << "\tWelcome to KeepPass\t\n";
    std::cout << "--------------------------------\n";
    print_menu();
    while (user_input.compare("4") != 0) {
        std::cin >> user_input;
        switch (stoi_with_check(user_input)) {
        case 1:

            break;
        case 2:
            break;
        case 3:
            break;
        default:
            std::cout << "[!] Invalid input.\n";
        }
        print_menu();
    }
    std::cout << "Exiting...\n";
}


int main()
{
    launch();
}