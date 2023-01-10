#ifndef CPPUTILITY_H
#define CPPUTILITY_H

#include <string>
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

unsigned int stoi_with_check(const std::string& str);

void reverse_arr(unsigned char* arr, int i, int f);
void left_rotate(unsigned char* arr, int d, int n);
void right_rotate(unsigned char* arr, int d, int n);

void printCharArr(unsigned char* arr, int len);
void print_menu();

#endif