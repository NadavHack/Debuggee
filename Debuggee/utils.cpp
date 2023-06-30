#include "defines.h"


//-------------Static Functions-------------//

void nice_print_ints(char* before, int* arr, int size) {
    for (int i = 0; i < size; i++) {
        printf("%s : %d\n", before, arr[i]);
    }
}

void hexdump(void* ptr, int buflen) {
    /*
    This function is printing 'buflen' bytes in hexdump starting from the pointer ptr
    hexdeump looks like that:

    offset:     hexbytes      string
    0x00000000  65 78 61 6d 70 6c 65     example    
    */ 

    unsigned char* buf = (unsigned char*)ptr;   //  Casting the void pointer to char pointer

    for (int i = 0; i < buflen; i += 16) {

        printf("%06x: ", i);    // Printing the offset in hex

        for (int j = 0; j < 16; j++)

            if (i + j < buflen)         // Checking if we are not out of the buffer length

                printf("%02x ", buf[i + j]);    // Printing hex characters of the buffer, 16 in a row

            else
                printf("   ");          // Printing a 3 spaces in case no more bytes to print, in order to complete the line nicefully 

        printf("    ");         // Printing a tab before printing the string representation of the hex bytes
        for (int j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');   // Ternary expression, if the byte is printable (if he has a ascii entry) we print it, else we print a dot
        
        printf("\n"); // Starting a new line 
    }
}

LPCVOID hexstring_to_addrs(const string& hexString) {
    stringstream ss;    // Creating a stream
    ss << hex << hexString; // Passing the hexString to a hex formatter
    
    void* address; 
    ss >> address; // Inputing the address into this pointer

    return (LPCVOID)address;  // Casting it to LPCVOID type
}

void disassemble(const uint8_t* buffer, size_t size, uint64_t starting_addrs, int max_inst) {
    /*
    The function recivies a pointer to a unsinged one byte integer, a size, and an starting address
    the function will print the assembly instruction represented by the bytes at the pointer specified for size bytes long
    */

    csh handle;     // This type is from the capstone library, we will use it to specify the arch we use and the disassembly mode CS_ARCH_X86 and CS_MODE_64
    cs_insn* inst;  // This is a pointer to an array of structures that will be populated with the instruction mnemonic and its parameters

    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);  // Here we initialize the capstone handler to disassemble x86 instructions set with 64 bit mode

    size_t count = cs_disasm(handle, buffer, size, starting_addrs, max_inst, &inst);
    
    /*
    the function returns the number of instructions it have disassembled,
    The parameters it gets are, a capstone handler, address to the buffer where the instructions are located, the size of the buffer, -
    - the maximum amount of instructions we want to disassemble (when set to 0 it means we want as much as possible),
    the last parameter is a pointer to a pointer, the cs_disas will create an array on the heap we will be able to through this pointer
    */

    for (int i = 0; i < count; i++) { // For each instruction that cs_disasm have preformed

        cout << "0x" << hex << inst[i].address;                                 // Printing the address of that instruction
        cout << "\t" << inst[i].mnemonic << " " << inst[i].op_str << endl;      // Printing tab the mnemonic(operation) space and arguments
    }
    cs_free(inst, count);       // Making sure the array of instruction is off the heap when we done using it to save space, this function clears the memory it took
    cs_close(&handle);              // Closing the handle to save space once more

    cout << dec;    // Because we used 4 lines up cout << hex; we have changed the output format, here we return it to decimal
}

unsigned char* hexstring_to_bytes(const string& hexString)
{   
    /*
    This function recives a string with hex chars and a size, the function will return a pointer to a byte array which has the actual bytes the hexstring represents
    */

    size_t size = hexString.length() / 2;           // Each byte is represented by 2 characters in the hex string so the overall size is devided by 2
    unsigned char* bytes = new unsigned char[size]; // Allocating buffer on the heap

    for (size_t i = 0; i < size; ++i)
    {
        string byteString = hexString.substr(i * 2, 2); // Cutting the string into 2 chars each time, each byte
        bytes[i] = static_cast<unsigned char>(stoi(byteString, nullptr, 16));
        /*
        stoi converts a string to an integer, first param is the string second is optional it is the index to start from, nullptr means do not use this argument,
        last param is the base to which we want to convert the string to, in this case hexadecimal is 16 so we pass 16
        static_cast converts the result which is in int to char
        */
    }

    return bytes;   // Here we return the pointer to the array on the heap
}


string integer_to_hexstring(uint64_t num) {
    stringstream ss;                // Creating a steam
    ss << "0x" << hex << num;       // Passing the number through the hex format    
    return ss.str();                // returning the string
}