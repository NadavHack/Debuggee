#include "defines.h"
#include "debuggie.h"


debuggie dbg; // Initiating a Debugger Instance, the constructor is called automatically

int main() {
	string in; // This string stores the choice between PID or Path

	printf("PID\\Path: ");	// Printing the options
	cin >> in;				// Inputing the user choice

	if (in == "PID") {	// Checking if its PID

		printf("Enter PID: ");
		int pid;		
		cin >> pid;
		/*
		Inputing the PID the user wants to attach to
		*/

		if (!dbg.attach((DWORD)pid))	// This function will attach to the process and return true if it succeeded, else it returns false
			return 1;					// If the attaching wasnt succesfull we return 1 and stop the debugger execution
		
	}
	else if (in == "Path") {		// If the user inputed Path this code will run

		printf("Enter path (with command line arguments if needed): ");
		string path;
		cin >> path;

		/*
		Here we input the path to the executable included with command line arguments if needed
		*/

		if (!dbg.load_process(path))	// This function will load the process under debugging mode and return true if it succeeded, else it returns false
			return 1;					// If the loading wasnt succesfull we return 1 and stop the debugger execution
		
	}
	else {
		/*
		If the user inputed something different then the options PID/Path we output "Option not found", return 0 and stoping the debugger execution
		*/
		cout << "Option not found..\nLeaving..";
		return 0;
	}
	
	get_user_input();	// This function runs an endless loop untill the debugger stops its execution,
	/*
	The function takes user input that indicates what function he wants to execute (set breakpoint, examine memory, continue, exit ...)
	*/

	
	return 0;
}


void get_user_input() {

	cout << "Try running 'help' if you dont know how to use this debugger" << endl; // Printing instructions for new users

	while (dbg.active) {	// As long as this variable is set to true the debugger execution is alive and we continue to take input

		string in;
		cout << "dbg> ";
		getline(cin, in);

		/*
		Taking user input storing it in "in" variable and comparing it to constant key words that execute different functions
		*/

		if (in == "help")
			print_help_msg();	// Printing the manual "how to use this debugger"

		else if (in == "exit")
			dbg.active = false;		// If the user wants to exit we set the active attribute to false

		else if (in == "step") {
			dbg.set_single_step();	// Setting the Trap bit in the EFLAGS register in order to perform single step exception
			dbg.get_debug_event(NULL, NULL, NULL, NULL);	// This function waits for the next debug event which must be EXCEPTION_SINGLE_STEP because the trap bit is on

			/*
			The handler at "get_debug_event" for EXCEPTION_SINGLE_STEP automaticaly disables the Trap bit in the EFLAGS register
			*/
		}

		else if (in == "continue") {
			dbg.get_debug_event(NULL, NULL, NULL, NULL);
			/*
			This function start with dbg.continue_dbg() which contnues the debugged process execution and waits for the next debug event
			*/
		}
			
		else if (in == "setb soft") {
			/*
			Placing a software breakpoint at a given address					0xCC  int3
			*/

			cout << "addrs(hex format) > ";
			string addrs;
			cin >> addrs;

			/*
			Here we take input from the user, we expect a hexstring (such as : 00132fda23) which is the virtual address at which the user is interested
			in placing a solf breakpoint.
			*/

			dbg.set_soft_breakpoint(hexstring_to_addrs(addrs));
			/*
			'hexstring_to_addrs' - Converts the string to LPCVOID type and returns it.
			Then we call 'set_soft_breakpoint' which places the soft breakpoint at the specified address
			*/
		}
		else if (in == "setb hard") {

			/*
			This function sets a hardware breakpoint at a given address size and condition
			*/

			cout << "Address (hex format)> ";
			string addrs;
			cin >> addrs;

			/*
			Inputing the address in hex format
			*/

			cout << "Length>";
			int length;
			cin >> length;

			/*
			Inputing the address length
			*/

			cout << "Conditions: 0:HW_EXECUTE 1:HW_WRITE 3:HW_ACCESS" << endl;
			cout << "Condition>";
			int condition;
			cin >> condition;

			/*
			Inputing the condition
			*/

			dbg.set_hard_breakpoint(hexstring_to_addrs(addrs), length, condition);
			/*
			Setting the hardware breakpoint at the given address length and condition,
			the function hexstring_to_addrs converts a string to LPCVOID which is a constant pointer to void
			*/
		}
		else if (in == "setb mem") {
			cout << "Address (hex format)> ";
			string addrs;
			cin >> addrs;

			/*
			Inputing the desired address
			*/

			cout << "Size>";
			int size;
			cin >> size;	// Inputing the size we want to set

			dbg.set_mem_breakpoint(hexstring_to_addrs(addrs), size); // Calling the function that sets the breakpoint,
			// hexstring_to_addrs - converts a hexstring to LPCVOID a pointer to void at which the hexstring is instructing
		}

		else if (in == "exa mem") {
			cout << "Address (hex format)> ";
			string addrs;
			cin >> addrs;

			cout << "Length>";
			int length;
			cin >> length;
			/*
			Inputing the virtual address the user wants to examine and the number of bytes he want to see
			*/

			void* buff = new char[length];	// Allocating place on the heap for the bytes from the debugged process memory
			int c = dbg.examine_memory(hexstring_to_addrs(addrs), buff, length);	// The function will populate 'buff' with the bytes from the process memory and return the number of bytes readed

			if (c > 0) {	// If an error occurred c will be equals to zero, here we make sure that it is bigger then 0 to hexdump it
				hexdump(buff, c);	// Hexdump 'c' bytes from 'buff'
			}

			delete[] buff; // Clears the memory
		}
		else if (in == "mod mem") {
			cout << "Address (hex format)> ";
			string addrs;
			cin >> addrs;

			cout << "Length>";
			size_t length;
			cin >> length;

			string hex_string;
			cout << "Enter Hexstring>";
			getline(cin, hex_string);	// This is used to escape the '\n' that stays in the 'cin' stream
			getline(cin, hex_string);

			// Inputing the address the user wants to change the values at, the number of bytes he wants to change and then the actual bytes in hex format

			void* buff = hexstring_to_bytes(hex_string);	// Here we convert the hexstring to actual bytes and storing them on the heap, the function returns a pointer to the buffer

			size_t c = dbg.modify_memory(const_cast<LPVOID>(hexstring_to_addrs(addrs)), buff, length); // Modifies the memory at the given address and bytes, the function returns the number of bytes that were writen

			if (c > 0) { // Here we make sure that no errors occured in the way
				hexdump(buff, c);		// Printing hexdump of the bytes, to indicate that the function have runned
			}
			

			delete[] buff; // Clearing the memory
		}

		else if (in == "show breakpoints") {
			dbg.print_breakpoints();	// Printing the aactive breakpoints
		}
		else if (in == "show threads") {
			dbg.enumerate_threads([](DWORD tid) {cout << "TID : " << tid << endl; });
			/*
			Enumerating through all the threads and printing each TID found using a quick defined lambda function
			*/
		}

		else if (in == "exa reg") {
			cout << "Enter TID : ";
			int tid;
			cin >> tid;
			/*
			Inputing the TID to examine its registers
			*/
			dbg.examine_registers(tid);		// Updating the 'context' attribute of the 'dbg' with the registers used by the given TID
			dbg.print_context(dbg.context);	// Printing the 'context', printing all important registers
		}	
		
		else if (in == "disas") {
			cout << "Address (hex format)> ";
			string addrs;
			cin >> addrs;

			cout << "Length>";
			size_t length;
			cin >> length;

			/*
			Inputing the address and nummber of bytes to disassemble
			*/

			void* buff = new char[length];	// Allocating space to hold the bytes from the debugged process
			dbg.examine_memory(hexstring_to_addrs(addrs), buff, length);	// Populating the 'buff' with the actual bytes

			disassemble((const uint8_t*)buff, length, (uint64_t)hexstring_to_addrs(addrs), 0);	// Disassembling the bytes at 'buff'

			delete[] buff; // Clearing space
		}

		else if (in == "trace") {
		dbg.trace_calls(); // Tracing calls of the program
}
	}

}

void print_help_msg() {
	cout << "Commands you can try:" << endl;
	// .. .. .. 
}


void print_instrucitons_at_runtime() {
	// Function not used
	auto dsias = [&]() {
		dbg.examine_registers(dbg.last_dbg_event.dwThreadId);
		char* buff = new char[16];
		dbg.examine_memory((LPCVOID)dbg.context.Rip, buff, 16);
		disassemble((const uint8_t*)buff, 16, dbg.context.Rip, 1);
	};
	while (dbg.active) {
		dbg.set_single_step();
		dbg.get_debug_event(NULL, NULL, NULL, dsias);

	}

}