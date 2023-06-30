#pragma once
#include "defines.h"

class debuggie;

#define MAX_SOFT_BREAKPOINTS 10 // Setting max amount for software breakpoints to be set in order to make the program simpler

/*
These values arent defined by the operating system
These values represent the bits 00 01 11 which are the allowed values for HARDWARE BREAKPOINTS CONDITIONS
*/

#define HW_EXECUTE	0x00000000
#define HW_WRITE	0x00000001
#define HW_ACCESS   0x00000003	

struct soft {
	/*
	This structure helps us handle the soft breakpoints array
	each soft breakpoint we save has to have the following attributes.
	*/
public:	// int3 
	BYTE original;	// This attribute is a BYTE and it will save the byte that was originally at the brekapoint address before we modified it into 0xCC byte code
					// We need to save it in order to write it back to the process memory when the breakpoint is hit

	LPCVOID addrs;	// Holds the virtual address of the soft breakpoint	

	bool active;	// Hold a boolien value to indicate if the breakpoint is active or not, we need this to know how many breakpoints are actialy active on the array so we can store more
};


class breakpoints
{
	/*
	This class handles all the things which are related to placing/removing/printing breakpoints
	*/
public:
	//--------------Members--------------
	soft s_brs[MAX_SOFT_BREAKPOINTS];	// Firsly we initialize an array of soft breakpoint
	debuggie* dbg;						// A pointer to a debugger type so we can have a reference to its functions and attributes

	SYSTEM_INFO sys_info;				// This will be used when placing memory breakpoints, this structure will be populated with the system information, our particular interest is PAGE_SIZE for placing memory breakpoint

	// -------------Methods--------------
	// De/Constructors
	breakpoints(debuggie* db);			// Here we initialize the attributes

	// Following functions are responsible for placing all kinds of breakpoints
	bool set_soft_breakpoint(LPCVOID addrs);

	bool set_hard_breakpoint(LPCVOID addrs, DWORD length, DWORD condition);

	bool set_mem_breakpoint(LPCVOID addrs, SIZE_T size);
	
	// Following functions are responsible for deleting all kinds of breakpoints
	void del_soft_breakpoint(LPCVOID addrs);
	void del_soft_breakpoint_by_slot(DWORD slot);	// This function takes a slot in the array 0-9 and removes it (makes its active attribute be false)

	void del_hard_breakpoint(LPCVOID addrs);
	void del_hard_breakpoint_by_slot(DWORD slot);	// This function takes a slot in the debug registers DR0-DR3 and disables it
	
	//Soft restore;
	bool restore_soft_break(LPCVOID addrs);			// This function restores the original byte in the process memory, and disables the breakpoint, if the breakpoint hasnt found in the array it will return false else true

	// Breakpoints hits handlers
	void soft_hit();

	// Printing stuff
	void print_breakpoints();						// This function simple prints all of the active software breakpoints in its array.


	//--------------friends :D-----------
	friend class debuggie;					// This statement anables the debuggie class access this class private members
};

