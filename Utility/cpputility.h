#ifndef CPPUTILITY_H
#define CPPUTILITY_H

#include <string>
#include <cstring>
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <random>

unsigned int stoi_with_check(const std::string& str);
int is_empty_file(FILE *fp);
std::string generate_salt(int len);

void string2hexString(unsigned char* input, char* output);
void reverse_arr(unsigned char* arr, int i, int f);
void left_rotate(unsigned char* arr, int d, int n);
void right_rotate(unsigned char* arr, int d, int n);


void printCharArr(unsigned char* arr, int len);
void print_menu();

#endif
