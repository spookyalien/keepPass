#include "cpputility.h"

std::vector<std::string> split (const std::string &s, char delim) {
    std::vector<std::string> result;
    std::stringstream ss (s);
    std::string item;

    while (getline (ss, item, delim)) {
        result.push_back (item);
    }

    return result;
}

void hex_str(std::string hex, unsigned char* output, int len)
{
    for (int i = 0; i < len*2; i += 2) {
        std::string hex_pair = hex.substr(i, 2);
        int intValue = std::stoi(hex_pair , nullptr, 16);
        unsigned char ucharValue = static_cast<unsigned char>(intValue);
        output[i / 2] = ucharValue;
    }
}

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

void delete_line(std::string path, std::string del_line) {
    std::string line;
    std::ifstream fin;
    std::cout << del_line << std::endl;
    
    fin.open(path);
    // contents of path must be copied to a temp file then
    // renamed back to the path file
    std::ofstream temp;
    temp.open("temp.txt");


    while (getline(fin, line)) {
        if (line.substr(0, del_line.size()) != del_line) {
            temp << line << std::endl;
        }
    }

    temp.close();
    fin.close();

    const char * p = path.c_str();
    remove(p);
    rename("temp.txt", p);
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
