#pragma once							// To avoid linker bugs we make sure this is included only once

/*
All of these libraries contains different functions we will use along the way, most of which are from "Windows.h"
*/
#include <stdio.h>
#include <capstone/capstone.h>
#include <Windows.h>
#include <string>
#include <iostream>
#include <TlHelp32.h>
#include <sstream>
#include <functional>



using namespace std;	// This anables us to use functions from std class without explictly indicating the function is from std; std::cout -> cout

//Utils defines, all of the following functions are implemented in the utils.cpp file

void hexdump(void* ptr, int buflen);	// This function prints buflen bytes from ptr in hexdump style

LPCVOID hexstring_to_addrs(const string& addrs);	// This function recives a const string by reference and converts it to LPCVOID type

void disassemble(const uint8_t* buffer, size_t size, uint64_t starting_addrs, int count);
/*
This function recives a pointer to unsinged 8 bit integers (unsigned byte), a size, starting_address and maximum number of instruction to disassemble
The function will read 'size' bytes from the 'buffer' and disassemble maximum 'count' number of instruction (when set to 0 it means disassemble as much as possible)
'starting_addrs' is the virtual address of the first instruction
*/

unsigned char* hexstring_to_bytes(const string& hexString); // This function recives a string that contains hex chars and it converts it to actual bytes, stores them on the heap and returns a pointer to them

string integer_to_hexstring(uint64_t num);


// The following functions implemented in pgn.cpp

void get_user_input(); // Main loop for taking user input and performing different actions

void print_help_msg(); // Prints a help message