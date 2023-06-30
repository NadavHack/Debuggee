#include "debuggie.h"
#include "breakpoints.h"

// Start end proceses
bool debuggie::load_process(string path) {	// Function recives a string path in the file system to the executable and spawns the process, if everything went as expected the function returns true, else false.

	STARTUPINFOA startupInfo = { sizeof(startupInfo) };	// Startupinfo structs indicates what *
	

	PROCESS_INFORMATION processInfo;	// This structure will be populated by the operating system after we will call CreateProcessA


	if (!CreateProcessA(			// The function returns True if the process created successfuly, else false
		nullptr,		// This is the path to the executable, when this is null, the next argument is expected to have the path included with command line arguments
		const_cast<LPSTR>(path.c_str()),	// This is the command line which to be executed
		nullptr,		// *
		nullptr,		// *
		FALSE,			// Gives the child process access to this process handles
		DEBUG_PROCESS,	// Automaticalty gives as access to WaitForDebugEvent function without using DebugActiveProcess function
		nullptr,			// *
		nullptr,		// * 
		&startupInfo,	// *
		&processInfo))	// Pointer to PROCESS_INFORMATION struct which contains usefull information about the process, the Operating System populates this at run time
	{
		cout << "Failed to create the process. Error: " << GetLastError() << endl;	// GetLastError return system error code, so if something went wrong we will know why
		return false;
	}

	cout << "Process created, PID: " << processInfo.dwProcessId \
		<< ", Main TID : " << processInfo.dwThreadId << endl;			// Outputs the process ID (PID) and the main thread ID (TID)
 
	this->process_handle = open_process(processInfo.dwProcessId);	// Open process returns a Handle with PROCESS_ALL_ACCESS so we can have full control over the process

	if (this->process_handle == INVALID_HANDLE_VALUE) {	// If open process went wrong the handle value is set to INVALID_HANDLE_VALUE
		return false; // Error occurred so returning false
	}

	this->active = true;						// This attribute is true as long as we are debugging a process
	this->pid = processInfo.dwProcessId;		// This attribute saves the PID of the debugged process for future use

	CloseHandle(processInfo.hProcess);	// Not needed, The operating system palpulates the PROCESS INFORMATION with a handle that has low permisions where we need PROCESS_ALL_ACCESS
	CloseHandle(processInfo.hThread);	// Not needed, Same reason as the above

	
	return true; // Returning true if everything went as expected
}

bool debuggie::attach(DWORD pid) { // The function recives an integer (DWORD is 4 bytes just as int) pid and attaches to is, if everything went as expected the function returns true, else false
	this->process_handle = open_process(pid);	// open process returns an handle to the process with PROCESS_ALL_ACCESS meaning we have full control over the process.

	if (this->process_handle == INVALID_HANDLE_VALUE) {	// If we dont have the right permision to attach or the PID is invalid the value of the HANDLE will be INVALID_HANDLE_VALUE
		cout << "Cant achive a valid handle" << endl;
		return false;			// Returning false to indicate that something went wrong
	}

	if (DebugActiveProcess(pid)) {	// This function recives a PID and makes the Operating System know we (this process) are ready to handle debuging events so each time a debug event will occur in the debugged process the operating system will pass control to us, via "WaitForDebugEvent"
		this->active = true;	// This attribute is true as long as the debuger is waiting for debugging events
		this->pid = pid;		// This attribute is the debugged process PID 
		cout << "Attached to : " << pid << " successfully" << endl;
		return true;	// Returning true to indicate everything went well
	}

	cout << "Cant attach to : " << pid << endl;
	return false;	// Returning false to indicate that something went wrong whole attaching
}

bool debuggie::dettach() {
	return DebugActiveProcessStop(this->pid);	// This function tells the operating system we are stoping to take care over debugging events, the operating system will stop passing us control over each debug event in the debugged process, by that we are stoping the debugging.
}

debuggie::debuggie() {
	cout << "Initialazing debuggie" << endl;

	this->active = false;	// Initializing attributes
	this->pid = 0;
	this->process_handle = INVALID_HANDLE_VALUE;
	
	this->brk_ps = new breakpoints(this);
	this->single_step = false;
	this->tracing = false;
}

debuggie::~debuggie() {
	cout << "Closing handles.." << endl;

	dettach();	// Dettaching from the process, letting the operating system know we are stoping the debugging.
	CloseHandle(this->process_handle);	// Closing handles gived by the operating system

}

// Static functions
HANDLE debuggie::open_process(DWORD pid) {
	return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); // Retrieving a HANDLE with the highest rights to debug a process, this handle will be needed in order to use other function in the future
}
void debuggie::print_context(CONTEXT context) {
	cout << "Register Values:" << endl;
	cout << "RAX: 0x" << hex << context.Rax << endl;	// cout << hex; intructs the program to format decimal(DWORD) numbers as hexadecimal
	cout << "RBX: 0x" << context.Rbx << endl;
	cout << "RCX: 0x" << context.Rcx << endl;
	cout << "RDX: 0x" << context.Rdx << endl;
	cout << "RSI: 0x" << context.Rsi << endl;
	cout << "RDI: 0x" << context.Rdi << endl;
	cout << "RBP: 0x" << context.Rbp << endl;
	cout << "RSP: 0x" << context.Rsp << endl;
	cout << "R8:  0x" << context.R8 << endl;
	cout << "R9:  0x" << context.R9 << endl;
	cout << "R10: 0x" << context.R10 << endl;
	cout << "R11: 0x" << context.R11 << endl;
	cout << "R12: 0x" << context.R12 << endl;
	cout << "R13: 0x" << context.R13 << endl;
	cout << "R14: 0x" << context.R14 << endl;
	cout << "R15: 0x" << context.R15 << endl;
	cout << "RIP: 0x" << context.Rip << endl;
	cout << "EFLAGS: " << context.EFlags << endl;
	cout << "-------------------------------------" << endl;
	cout << dec;	// cout << hex makes the output appear in hexadecimal, this format stays still untill I intruct cout<<dec; to return to decimal format
}

void debuggie::void_call_it(const function<void()>& func) { // The function gets a function pointer and calls that function, the called function must return void and have no parameters
	if (func != NULL)	// Checks if the function exists (not points to null)
		func();		// Calls the function
}

// Memory funcions
void debuggie::examine_registers(DWORD tid) {

	this->context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;	// Bit wise operation OR that includes CONTEXT_FULL with CONTEXT_DEBUG_REGISTERS, this will indicate the operating system to populate the rest of the CONTEXT structure with that information
	HANDLE th_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);	// Geting a handle with all rights to a thread 
	
	if (th_handle == INVALID_HANDLE_VALUE) {
		cout << "Can't retrieve a valid handle to tid " << tid << endl;
		return;
	}

	GetThreadContext(th_handle, &this->context);	// This function will populate the context structure with the registers information we desire, using the handle retrieved before

	CloseHandle(th_handle);	// Closing the handle to save space in the operating system

	//print_context(this->context);	// This function will simply print all the interesting registers in this context
}

void debuggie::modify_registers(DWORD tid, CONTEXT new_context) {

	HANDLE th_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);	// Retrieving a handle to a TID with all rights
	if (th_handle==INVALID_HANDLE_VALUE) {		// Checking we have a valid handle, if not we return
		cout << "Cant modify registers at thread " << tid << endl;
		return;
	}

	SetThreadContext(th_handle, &new_context);	// Setting the new context to the specified thread

	//cout << "TID " << tid << " registers been modified";
}

SIZE_T debuggie::examine_memory(LPCVOID baseAddress, LPVOID buffer, SIZE_T size) {	// The function will read "size" bytes from "baseAddress" in the process to "buffer"

	SIZE_T count=0;		// This will be populated with the size that have been readed from the process, if it remains 0 then it indicates that no bytes were readed
	DWORD oldPrem;		// This will hold the value of the old premissions the process region had

	VirtualProtectEx(this->process_handle, (LPVOID)baseAddress, size, PAGE_EXECUTE_READWRITE, &oldPrem);
	// 
	// This function is changing the premision on a region to "PAGE_EXECUTEEEEE_READWRITE" (all the premisions enabled). It recives as parameters, the process handle, "baseAddress" is the virtual address we want to change prem, "size" is the size we want to change, PAGE_EXECUTE_READWRITE is the new premisions, and &old will be populated with the original premisions

	if (ReadProcessMemory(this->process_handle, baseAddress, buffer, size, &count)) { // The function returns true if everything went well, else false. first parameter is a handle to the process we want to read from, "baseAddress" is the virtual address of that process of which we want to read from, "buffer" is a pointer to the buffer that will store the readed data, "size" holds the amount of bytes to be readed ,"&count" will be populated with the actual amout of bytes taht were readed.
		//cout << "Successfully readed " << count<< " bytes from " << baseAddress << endl;
	}
	else {
		cout << "Failed reading " << size << " bytes from " << baseAddress << endl;
	}	// In both cases, we are not returning because we need to retrieve the original premisions

	VirtualProtectEx(this->process_handle, (LPVOID)baseAddress, size, oldPrem, NULL); // Making sure the old premisions remain so the program can continue its execution normaly
	

	return count; // Returning the number of readed bytes from the process
}

SIZE_T debuggie::modify_memory(LPVOID baseAddress, LPCVOID buffer, SIZE_T size) { // The function will write "size" bytes from "baseAddress" in the process to "buffer"

	SIZE_T count=0;	// This will be populated with the size that have been writed to the process, if it remains 0 then it indicates that no bytes were writed
	DWORD oldPrem;	// This will hold the value of the old premissions the process region had
	
	VirtualProtectEx(this->process_handle, (LPVOID)baseAddress, size, PAGE_EXECUTE_READWRITE, &oldPrem);
	// This function is changing the premision on a region to "PAGE_EXECUTEEEEE_READWRITE" (all the premisions enabled). It recives as parameters, the process handle, "baseAddress" is the virtual address we want to change prem, "size" is the size we want to change, PAGE_EXECUTE_READWRITE is the new premisions, and &old will be populated with the original premisions

	if (WriteProcessMemory(this->process_handle, baseAddress, buffer, size, &count)) {// The function returns true if everything went well, else false. first parameter is a handle to the process we want to write to, "baseAddress" is the virtual address of that process of which we want to write to, "buffer" is a pointer to the buffer that stores the bytes we want to write, "size" holds the amount of bytes to be writed from "buffer" ,"&count" will be populated with the actual amout of bytes that were writed.
		
		cout << "Successfully writed " << count << " bytes to " << baseAddress << endl;
	}
	else {
		cout << "Failed writing " << size << " bytes to " << baseAddress << endl;
	}// In both cases, we are not returning because we need to retrieve the original premisions

	VirtualProtectEx(this->process_handle, (LPVOID)baseAddress, size, oldPrem, NULL);
	// Making sure the old premisions remain so the program can continue its execution normaly


	return count; // Returning the number of writed bytes to the process
}


//Debug functions

void debuggie::enumerate_threads(const function<void(DWORD)>& callback) { // The function will print each TID that belongs to our debugged process, it gets a pointer to a function that recives an integer (DWORD) and if it not equals NULL we will call this function. with this approach we can later extand this function to act differently each time

	THREADENTRY32 th_entry;		// This structure will be populated by the operating system, it have attributes such as TID and PID which help us to locate our debugged process threads
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);	// This function takes a snapshot of all the running threads in the system, with the handle it returns we are able to loop on each thread in the system/
																		// The first parameter TH32CS_SNAPTHREAD indicates we want to snapshot all threads, the second parameter can be anything in our case 
	th_entry.dwSize = sizeof(th_entry);

	if (snapshot == INVALID_HANDLE_VALUE) { // Making sure that the function succeeded, if not it will return INVALID_HANDLE_VALUE and we will return

		cout << "Coulnt take a snapshot" << endl;
		return;
	}

	int count = 0;		// This variable will keep track of the number of threads allready found, it will number the threads starting from zero
	Thread32First(snapshot, &th_entry);	// This function will populate the th_entry with the first thread it found, we can think of this as a list where Thread32First will return as to the root and each Thread32Next will get us to the next node in the list
	

	do {

		if (th_entry.th32OwnerProcessID == this->pid) {		// Checking if the thread belongs to our debugged process, if it is we will print its TID
			//cout << "TID " << count << " : " << th_entry.th32ThreadID << endl;

			if (callback != NULL) {	// Checking if the user passed a special function to handle each thread, if it has we call it and pass it the TID we found
				//cout << "Calling costum callback" << endl;
				callback(th_entry.th32ThreadID);
			}

			count++; // Increamenting count by 1
		}
	} while (Thread32Next(snapshot, &th_entry));	// While Thread32Next still returns a valid thread entry we will keep looping through 
	
	CloseHandle(snapshot);
}

void debuggie::get_debug_event(const function<void()>& segCB, const function<void()>& brCB, const function<void()>& guardCB, const function<void()>& stepCB) { 
	/*
	This function recieves 4 function pointers that will be called when their corresponding event happens, these are the events handlers for each debug event that might occur.
	The function will waits halts the debugger execution untill a debug event occurrs
	*/
	
	bool found = false; // Untill a EXCEPTION_DEBUG_EVENT is found this variable will remain false, and the program will continue its execution untill a EXCEPTION_DEBUG_EVENT occur

	while (!found) { // Continue running untill a debug event

		this->continue_dbg();	// Making sure the debugged program is running; 

		if (WaitForDebugEvent(&this->last_dbg_event, INFINITE)) { // The function will wait for a debug event

			cout << "Debug event recived : " << this->last_dbg_event.dwDebugEventCode << " TID : " << this->last_dbg_event.dwThreadId << endl; // Printing the debug event

			if (this->last_dbg_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) { // Checking to see if the DebugEventCode is EXCEPTION_DEBUG_EVENT (Other options are Module loading, Thread Creation)

				found = true; // Making sure that the loop will end after the handler will be called
				
				switch (this->last_dbg_event.u.Exception.ExceptionRecord.ExceptionCode) {	// Switch case for what debug event have occurred

				case EXCEPTION_ACCESS_VIOLATION:
					/*
					This debug event will happen in case of a SEGMENTATION FAULT,
					that is when the debugged program is trying to access regions in memory with the wrong protections
					*/
					cout << "Access violation detected at : " << this->last_dbg_event.u.Exception.ExceptionRecord.ExceptionAddress << endl; // Printing Segmentation fault address
					void_call_it(segCB);	// Calling the event handler
					break;					// Breaking out of the switch case

				case EXCEPTION_BREAKPOINT:	// Soft breakpoints handler
					/*
					* 0xCC int3
					Only software breakpoints will be catched here,
					Whenever the debuged process will run 0xCC byte this code will run
					*/
					cout << "Breakpoint hit at " << this->last_dbg_event.u.Exception.ExceptionRecord.ExceptionAddress << endl; // Printing the breakpoint address
					if (this->brk_ps->restore_soft_break(this->last_dbg_event.u.Exception.ExceptionRecord.ExceptionAddress)) // This function will return the original byte to its place, and by that remove the breakpoint
						this->brk_ps->soft_hit();			// If the breakpoint is indeed part of the user defined breakpoints we want to decrement RIP by 1 so we return to its original value
					else
						found = false;		// If the breakpoint isnt related to our array of breakpoints we dont want to stop the process, so we set the found to false again

					void_call_it(brCB);		// Calling the event handler
					break;					// Breaking out of the switch case

				case EXCEPTION_GUARD_PAGE:	// Memory breakpoints handler
					/*
					Whenever the debugged process will try to access a GUARDED PAGE this code will run,
					Afterwards the operating system will automatically turn off the GUARD bit so we need no worry to restore the old protections
					*/
					cout << "Guarded page exception at " << this->last_dbg_event.u.Exception.ExceptionRecord.ExceptionAddress << endl;
					void_call_it(guardCB);	// Calling the event handler
					break;					// Breaking out of the switch handler

				case EXCEPTION_SINGLE_STEP:	// Single step || Hardware breakpoints handler
					/*
					Both hardware breakpoints and Single Step Traps will end up in this code's execution.
					*/

					if (this->tracing) {	// If the program is running the trace_calls function we do not want it to stop
						found = false;				// Setting the found to false so the tracing can continue
						this->set_single_step();	// Setting the single step so it will catch all of the executed instruction
						void_call_it(stepCB);	// Calling the trace_calls nested lambda function
						break;						// Breaking out of the swich
					}

					cout << "Single step | Hardware breakpoint; at address " << this->last_dbg_event.u.Exception.ExceptionRecord.ExceptionAddress << endl;

					if (this->single_step) {	// Checking to see if the single_step boolian is on, in case it is we call the single step handler
						//cout << "Trap bit off" << endl;
						this->del_single_step();	// Deleting the single step trap, turning of EFLAG trap bit.
					}

					void_call_it(stepCB);	// If is wasn't a single step exception we call the hardware breakpoints handler
					break;		// Breaking out of the switch

				default:
					cout << "Wierd???" << endl;
					break;
				}

				if (found && this->tracing) {	// If a user defined debug event occured the found flag will be ON, if it happend under tracing we would like to stop the tracing
					this->tracing = false;		// So the user command promt will appear
				}
			}
		}
	}
}

void debuggie::continue_dbg() {
	/*
	This function will make the PID's TID execution continue normally, DBG_CONTINUE indicates to the process that it should continue normally.
	Other options are DBG_EXCEPTION_NOT_HANDLED and DBG_EXCEPTION_HANDLED.
	*/
	ContinueDebugEvent(this->last_dbg_event.dwProcessId, this->last_dbg_event.dwThreadId, DBG_CONTINUE);
}

//breakpoitns
/*
All of the following functions (Untill the "Steping" command) are just calling other functions which are documented on their page (breakpoints.cpp)
*/
void debuggie::set_soft_breakpoint(LPCVOID addrs) {
	this->brk_ps->set_soft_breakpoint(addrs);
}

void debuggie::set_hard_breakpoint(LPCVOID addrs, DWORD length, DWORD condition) {
	this->brk_ps->set_hard_breakpoint(addrs, length, condition);
}

void debuggie::set_mem_breakpoint(LPCVOID addrs, SIZE_T size) {
	this->brk_ps->set_mem_breakpoint(addrs, size);
}

void debuggie::del_soft_breakpoint(LPCVOID addrs) {
	this->brk_ps->del_soft_breakpoint(addrs);
}
void debuggie::del_soft_breakpoint_by_slot(DWORD slot) {
	this->brk_ps->del_soft_breakpoint_by_slot(slot);
}

void debuggie::del_hard_breakpoint(LPCVOID addrs) {
	this->brk_ps->del_hard_breakpoint(addrs);
}
void debuggie::del_hard_breakpoint_by_slot(DWORD slot) {
	this->brk_ps->del_hard_breakpoint_by_slot(slot);
}

// Steping

void debuggie::set_single_step() {

	auto do_for_all_threads = [&](DWORD tid) {
		/*
		This lambda function will be called for each TID of the debugged process,
		In order to place the breakpoint under all threads.

		[&] - indicates that the variables in this function are passed by reference ('this' variable in this case)
		() - indicates that the function isnt taking any arguments
		*/
		this->examine_registers(tid); // Populating the CONTEXT structure located at (this->context)
		this->context.EFlags |= 0x100; // Setting the TRAP bit on, using the bit wise operation OR
		this->modify_registers(tid, this->context); // Applying the new context
	};

	this->enumerate_threads(do_for_all_threads); // Enumerate threads will call this costume function foreach thread related to our debugged process
	this->single_step = true;					// Makin sure to update the single_step variable to true so that in the next EXCEPTION_SINGLE_STEP the program will know it was a single step trap and not a hardware breakpoint
}
void debuggie::del_single_step() {

	auto do_for_all_threads = [&](DWORD tid) {
		/*
		Very similar to the function in "set_single_step"
		this function will be called foreach thread associated with the debugged process
		*/
		this->examine_registers(tid); // Updating the context structure
		this->context.EFlags &= ~0x100; // Setting the TRAP bit off using the AND and NOT logical bit wise operations
		this->modify_registers(tid, this->context);// Applying the new changes
	};

	this->enumerate_threads(do_for_all_threads); // This function will call 'do_for_all_threads' foreach TID he finds that is related to the debugged process PID
	this->single_step = false;			// Making sure to set the single_step to false so that the next EXCEPTION_SINGLE_STEP will be known for a hardware breakpoint and not a single step trap
}

// Printing stuff

void debuggie::print_breakpoints() {
	/*
	This function will print which Software breakpoints and Hardware breakpoints are currently set.
	*/

	this->brk_ps->print_breakpoints(); // This function will print all the Soft breakpoints

	cout << "Hardware breakpoints:" << endl;
	cout << "DR7 : " << this->context.Dr7 << endl;
	for (int i = 0; i < 4; i++) {
		if (this->context.Dr7 & (3 << i * 2)) { // This bit wise operation checks if the L G bits are on, for each L G bits on they find the print the corresponding debug register
			switch (i) {
			case 0:
				cout << "Dr0 active : 0x" << hex << this->context.Dr0 << endl;
				break;
			case 1:
				cout << "Dr1 active : 0x" << this->context.Dr1 << endl;
				break;
			case 2:
				cout << "Dr2 active : 0x" << this->context.Dr2 << endl;
				break;
			case 3:
				cout << "Dr3 active : 0x" << this->context.Dr3 << endl;
				break;
			}
		}
	}

	cout << dec;	// Making sure the format string is back to default (cout << hex; makes all calls to it late appear in hexadecimal format) cout << dec; sets the format to decimals

}


// Special functions

void debuggie::trace_calls() {
	/*
	This function creates a string of all calls that the process executed and prints them in a string each time new ret or call instruction have been executed
	Dogma: 
	0x44332211 -called-> 0x223213 -> 0xaaaaa213 -called-> 0x213123
	0x44332211 -> 0x223213
	0x44332211 -> 0x223213 -> 0xff2132
	0x44332211 -> 0x223213
	0x44332211

	The function will step through each intruction read its RIP register and the instruction op code it have, if it equals 0xe8 = call or 0xc3 = ret it will add the RIP or remove the last one accordingly 
	*/

	string trace_chain = "";	// This string will hold the chain to be printed such: 0x44332211 -> 0x441267d -> 0xf77231233
	this->tracing = true;		// This variable will indicate that the process is running trace calls, It will stay true untill a user defined breakpoint will occurr

	bool add_next_rip = false;	// This variable indicates if we need to add the nex RIP to the 'trace_chain', when a call instruction happens we step and then add the RIP using this variable
	bool print_now = false;		// This variable indicates if we need to write the trace_call string now or we should wait for another instruction

	auto trace_func = [&]() {
		/*
		This lambda function will be executed foreach instruction (step) that the debugged process executes
		this lambda will read 1 byte from RIP and check if it equals to CALL or RET
		then it will set some flags 'print_now' or 'add_next_rip' and update the 'trace_chain' if needed
		*/

		BYTE op_code;		// Here we'll store the operating (byte) code that RIP is pointing to.

		this->examine_registers(this->last_dbg_event.dwThreadId);						// Updating the context with the current thread registers
		this->examine_memory((LPCVOID)this->context.Rip, &op_code, 1);	// Reading one byte at RIP from the debugged process memory

		if (add_next_rip) {
			/*
			Cheking if we need to add the current RIP to the string, (In case the last instruction was a call to this instruction)
			*/
			trace_chain += " -called-> " + integer_to_hexstring(this->context.Rip);	// Integet to hexstring will convert uint64_t (64 bit integer) to a hexstring
			add_next_rip = false;												// Reseting the add_next_rip back to false so that it would not keep on adding wrong addresses
			print_now = true;													// Indicating that we want to print the string we got so far
		}

		if (op_code == 0xe8) { // IF (OPERATION_CODE == CALL)
			/*
			If the instruction is call we want to add it into the string
			*/
			if (trace_chain == "")	// If the string is empty we would not want to add -> before it
				trace_chain += integer_to_hexstring(this->context.Rip);
			else
				trace_chain += " -> " + integer_to_hexstring(this->context.Rip); // -> indicates that we have been executing normaly to this point (without call instructions)

			add_next_rip = true;	// Indicating that we want to catch the next instruction
		}

		else if (op_code == 0xc3 && trace_chain!="") {	// IF (OPERATION CODE = RET AND THE STRING != "")
			/*
			In case we got a ret instruction we want to remove all the last part of the string untill the -called-> because it is the place the program execution returns to
			Example : 
			0x44332211 -called-> 0x11223344 -> 0x11223355 -called-> 0xfff123123
			ret
			REMOVED:  -called-> 0xfff123123
			0x44332211 -called-> 0x11223344 -> 0x11223355
			ret
			REMOVED: -called-> 0x11223344 -> 0x11223355
			0x44332211
			*/
			int pos = trace_chain.find_last_of(" -called-> ");	// Getting the last index of " -called-> " 
			trace_chain = trace_chain.substr(0, pos-10);		// Getting the string from index 0 to the  -called->  minus 10 because the length of " -called-> " is 10
			print_now = true;									// Indicating we want to print the updated string
		}

		if (print_now) {	// If print now is set we simply print the string
			cout << trace_chain << endl;
			print_now = false;		// Reseting 'print_now'
		}
		
	};

	this->set_single_step(); // Setting single step on
	this->get_debug_event(NULL, NULL, NULL, trace_func);	// This will run until a breakpoint or other debug event and then return
	this->del_single_step();								// Deleting the single step functionality
}