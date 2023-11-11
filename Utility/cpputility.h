#ifndef CPPUTILITY_H
#define CPPUTILITY_H

#include <string>
#include <cstring>
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <random>
#include <iostream>
#include <fstream>
#include <sstream>

#define DEFAULT_LEN 16

typedef void* (*memset_t)(void*, int, size_t);
unsigned int stoi_with_check(const std::string& str);
int is_empty_file(FILE *fp);
std::string generate_salt(int len);
std::vector<std::string> split (const std::string &s, char delim);
void delete_line(std::string path, std::string del_line);
void hex_str(std::string hex, unsigned char* output, int len);
void string2hexString(unsigned char* input, char* output);
void reverse_arr(unsigned char* arr, int i, int f);
void left_rotate(unsigned char* arr, int d, int n);
void right_rotate(unsigned char* arr, int d, int n);

void cleanse(void* ptr, size_t len);

static volatile memset_t memset_func = memset;

#endif
