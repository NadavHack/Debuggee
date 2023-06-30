#pragma once
#include "defines.h"
#include "breakpoints.h"



class debuggie
{
    /*
    This class will hold all the important methods and attributes needed in order to create a debugger
    */
public:
    //Consructor and deconsructor
    debuggie();     // Initializes attributes
    ~debuggie();    // Closing handles and freeing memory

    //Starup related
    bool load_process(string path); // Loading a process into memory under debugging mode
    bool attach(DWORD pid);         // Attaches to a running process

    //Fini section
    bool dettach();     // Dettachess from an attached process



    //Debugging function

    void enumerate_threads(const function<void(DWORD)>& callback);  // This function will go through all threads found related to the debugged process and call foreach of these
    // the function given as an argument with the TID it have found

    // Classics debug functions
    void examine_registers(DWORD tid);  // This function recives a TID and populates the attribute 'context' with the values of registers used by the given thread
    void modify_registers(DWORD tid, CONTEXT new_context);  // This function recives a TID and a new context and updates the registers values to the new context argument

    SIZE_T examine_memory(LPCVOID baseAddress, LPVOID buffer, SIZE_T size);
    /*
    This function recives a virtual address of the debugged process, a buffer, and size.
    The function will read 'size' bytes from the debugged process memory 'baseAddress' and store them in the 'buffer'
    */
    SIZE_T modify_memory(LPVOID baseAddress, LPCVOID buffer, SIZE_T size);
    /*
    This function recives a virtual address of the debugged process, a buffer, and size.
    The function will write 'size' bytes to the debugged process memory from 'buffer' to 'baseAddress'
    */

    void get_debug_event(const function<void()>& segCB, const function<void()>& brCB, const function<void()>& guardC, const function<void()>& stepCB);
    /*
    This fucntion recives 4 different callback functions for different debugging scenarios (seg fault, soft breakpoint, guard page, single step | hardware breakpoint)
    The function waits until one of these debug events occurre and then it calls the corresponding function
    */
    void continue_dbg();
    /*
    Continues the debugged process in case it was halt
    */

    void set_single_step();     // Sets the single step functionality, (turns on the Trap bit in EFLAGS)
    void del_single_step();     // Deletes the single step (turns off the Trap bit in EFLAGS)

    //breakpoints; These functions place/deletes differente types of breakpoints
    void set_soft_breakpoint(LPCVOID addrs);
    void del_soft_breakpoint(LPCVOID addrs);
    void del_soft_breakpoint_by_slot(DWORD slot);

    void set_hard_breakpoint(LPCVOID addrs, DWORD length, DWORD condition);
    void del_hard_breakpoint(LPCVOID addrs);
    void del_hard_breakpoint_by_slot(DWORD slot);

    void set_mem_breakpoint(LPCVOID addrs, SIZE_T size);

    // Print stuff
    void print_breakpoints();   // Prints all kinds of active breakpoints

    // Special debuggie functions

    void trace_calls(); // This function prints a 'tree' of function calls the debugged process is performing

    //Static Ezer functions
    static void print_context(CONTEXT c);                       // Prints all general purpuse registers and RIP RSP RBP.. 
    static void void_call_it(const function<void()>& segCB);    // Calls the given function if it is not set to null

    //---------------Public-Members---------------
    CONTEXT context;        // This is a structure containing many registers and it is being populated by 'examine_registers' function
    bool active;            // Indicates if the debugger is running or not


    DEBUG_EVENT last_dbg_event; // This structure have all the information related to debug event, and is being populated by 'get_debug_event' function

private:
    //---------------Private-Members---------------
    //process information
    DWORD pid;              // This will store the PID of the debugged process
    HANDLE process_handle;  // This is a handle to the debugged process, without this we cannot use functions such as 'examine_memory' 'modify_memory'...


    //debugger stuff
    breakpoints *brk_ps;    // This is a calss implemented at 'breakpoint.cpp' and it contains all kind of functions related to setting and deleting breakpoints
        
    bool single_step;       // This variable indicates if we are under single_step exception, in order to distinguish between hardware breakpoint exception and single step
    bool tracing;           // This variable is used to indicate if we are performing 'trace_calls' function or not


    //Static functions
    static HANDLE open_process(DWORD pid);  // This function gets a process handle of a given PID and returns it
    

    //-------friends :D ---------

    friend class breakpoints;   // This statement anables the 'breakpoints' class to access the 'debuggie' private attributes
    
};

