#include "breakpoints.h"
#include "debuggie.h"

//Init fini
breakpoints::breakpoints(debuggie *dbg) {
	this->dbg = dbg;								// Setting the reference to the debuggie class
	ZeroMemory(this->s_brs, sizeof(this->s_brs));	// making sure everything is set to 0
	GetSystemInfo(&this->sys_info);					// Populates the SYSTEM_INFORMATION structure with our desired information (PAGE_SIZE)
}


//Setting breakpoints
bool breakpoints::set_soft_breakpoint(LPCVOID addrs) {
	
	BYTE CCbyte = 0xcc;	// Holds the byte we want to write to the process memory

	for (auto& br : this->s_brs) { // auto& automatically creates for us a reference to each element in the s_bts (software breakpoints) array

		if (br.addrs==addrs || !br.active) {	// Looking for a free slot, or a slot where its address is already equals to the address we wish to set a breakpoint at
			
			if (!dbg->examine_memory(addrs, &br.original, sizeof(br.original))) {
				/*
				Reading 1 byte from the prccess memory and storing it at &br.original,
				the function will return the number of the bytes that were readed, so if it is 0 -> !0 = !false = true
				Will make this code run
				*/
				return false;// Indicating that something went wrong
			}

			if (!dbg->modify_memory((LPVOID)addrs , &CCbyte, sizeof(CCbyte))) {
				/*
				Writing to the process memory the 0xCC byte at the breakpoint address,
				similar to the if statement above.
				*/
				return false; // Indicating that something went wrong
			}

			cout << "Soft breakpoint set at :" << addrs << endl;
			br.active = true;	// Setting the br.active to true so that the next soft brearkpoint to be set would not override this one.
			br.addrs = addrs;	// Remembering the address at which the breakpoint resides for restoring it later
			return true;		// Indicating all went as expected and the breakpoint is up.
		}
	}
	/*
	In case of all the br.active were true then the user must remove some of its breakpoints in order to place new ones
	*/
	cout << "Failed : Maximum amout of breakpoints reached, please remove one in order to place a new one" << endl;
	return false; // Indicating something went wrong
}

bool breakpoints::set_hard_breakpoint(LPCVOID addrs, DWORD length, DWORD condition) {

	if (length != 1 && length != 2 && length != 4) {
		/*
		Hard breakpoints as specified in the book must have a lenght of 1 ,2 or 4
		any other numbers will break the excepted behavior of the program.
		*/
		cout << "Unable to set hardware breakpoint with length " << length << endl;
		return false;
	}

	length--; // Because the mapping between length and bits is as follows we must decrement by 1; 1 = 00, 2 = 01, 4 = 11

	if (condition != HW_ACCESS && condition != HW_WRITE && condition != HW_EXECUTE) {
		/*
		Making sure the user choose one of the options above in case he havent the program behavior may change or break
		*/
		cout << "Unable to set hardware breakpoint with condition " << condition << endl;
		return false;
	}
	

	auto take_care_tid = [&](DWORD tid) {
		/*
		This lambda function will be run foreach tid and will set its DR7 and DR0-DR3 to its appropriate value in order to place the hard breakpoint
		The lambda function recives DWORD tid, and it is accessing all veriable in this function by reference thanks to "[&]"
		*/
		dbg->examine_registers(tid);	// Populating the CONTEXT structute..
		int available_slot = -1;		// This variable will hold the available slot for the breakpoint to reside, if its stays -1 then all of the hardwere breakpoints are occupied

		//cout << "TID found : " << tid << endl;

		for (int i = 0; i < 4; i++) {	// Looping through 0-3 = DR0-DR3

			if ((dbg->context.Dr7 & (0x3 << (i * 2))) == 0) { // Checking the contents of Dr7 to determine if the corresponding debug registed is occupied or not using AND and SHIFT bit wise operators
				available_slot = i;	// If we found a free slot we set it to "available_slot" and break the loop
				break;			// Breaking the loop
			}
		}

		cout << "Slot found : " << available_slot << endl;

		switch (available_slot) { // Switching available slot in order to update the register of the dbg->context corresponding to the available slot
		case 0:
			dbg->context.Dr0 = (DWORD64)addrs;
			break;
		case 1:
			dbg->context.Dr1 = (DWORD64)addrs;
			break;
		case 2:
			dbg->context.Dr1 = (DWORD64)addrs;
			break;
		case 3:
			dbg->context.Dr1 = (DWORD64)addrs;
			break;
		default:
			cout << "All hardware breakpoints are in use\ndelete in order to place new ones\n";	// In case where available slot stays -1 that this code will run to notify the user that all hard breakpoint are in use
			return false; 
		}

		dbg->context.Dr7 |= (0x3 << (available_slot * 2)); // Activating the breakpoint at DR7 using the OR adn SHIFT bit wise operators
		dbg->context.Dr7 |= (condition << (16 + available_slot * 4)); // Setting condition using the OR adn SHIFT bit wise operators
		dbg->context.Dr7 |= (length << (18 + available_slot * 4)); // Setting length using the OR adn SHIFT bit wise operators


		dbg->modify_registers(tid, dbg->context);	// Applying the changes to the TID
		
	};
	dbg->enumerate_threads(take_care_tid); // Runs the "take_care_tid" to all of the TIDs 
	cout << "Hardware breakpoint placed : " << addrs << endl;
	return true; // Returning true because everything went well
}

bool breakpoints::set_mem_breakpoint(LPCVOID addrs, SIZE_T size) {
	
	MEMORY_BASIC_INFORMATION mbi;	// This structure will be populated with the information needed by us in order to place the memory GUARD protection,
									// From this structure we will know the memory's region protection, and base address

	if (!VirtualQueryEx(dbg->process_handle, addrs, &mbi, sizeof(mbi))) {
		/*
		VirtualQueryEx will populate MBI according to the address we want to examine
		*/
		cout << "Something went wrong while memory querying address " << addrs << endl;
		return false;
	}

	PVOID current_address = mbi.BaseAddress; // We store the base address of the particular memory region

	while ((DWORD)current_address <= (DWORD)addrs + size) {
		/*
		If the 'current_address' is less the the addition between the memory breakpoint and its size then we need to do the same thing to the next memory page
		*/
		
		DWORD old_protection; // This will hold the old protection, we will not use this.

		if (!VirtualProtectEx(dbg->process_handle, current_address, this->sys_info.dwPageSize, mbi.Protect | PAGE_GUARD, &old_protection)) {
			/*
			VirtualProtectEx will change the protection on the memory region we specify.
			The parameters are, the process handle, the base address of the memory region, the page size, the new protection and lastly and address to story the old protection.
			We will not use the last parameter as the operating system restores the old protections by it self (It sets the GUARD bit off after GUARD_EXCEPTION occurred)
			*/
			cout << "Cant change protection at address " << current_address << endl;
			return false;	// Returning false to indicate something went wrong
		}
		cout << mbi.BaseAddress << " " << mbi.Protect << " " << this->sys_info.dwPageSize << " " << old_protection << endl;

		uintptr_t numeric_address = reinterpret_cast<uintptr_t>(current_address);	// Casting PVOID to uintptr_t, so we can perform arithmetic operations on it
		numeric_address += this->sys_info.dwPageSize;								// Adding page size in order to get to the next base address

		current_address = reinterpret_cast<PVOID>(numeric_address);					// Casting back to PVOID so that we can use it as a parameter in VirtualProtectEx
	}
	cout << "Memory breakpoint set at " << addrs << " with size " <<size << endl;
	return true; // Returning ture to indicate everything is fine.
}


//Deleting breakpoints
void breakpoints::del_soft_breakpoint(LPCVOID addrs) {
	// Restore soft breakpoint serves the functionality we need to delete the breakpoint
	restore_soft_break(addrs);
}
void breakpoints::del_soft_breakpoint_by_slot(DWORD slot) {
	// Same as before..
	restore_soft_break(this->s_brs[slot].addrs);
}

void breakpoints::del_hard_breakpoint(LPCVOID addrs) {
	/*
	In order to delete a hardware breakpoint we need to know on which debug register it is located.
	After we check all the DRs and find the slot we call del_hard_breakpoint_by_slot which will remove the breakpoints from all TIDs
	*/
	int slot = -1; // Stores the slot 0-3 (DR0-DR3) on which the address is found, if this variable stays -1 then no breakpoint with this addrs is active
	
	if (dbg->context.Dr0 == (DWORD64)addrs) {
		slot = 0;
	}
	else if (dbg->context.Dr1 == (DWORD64)addrs) {
		slot = 1;
	}
	else if (dbg->context.Dr2 == (DWORD64)addrs) {
		slot = 2;
	}
	else if (dbg->context.Dr3 == (DWORD64)addrs) {
		slot = 3;
	}
	if (slot == -1) {
		cout << "Address not found in any debug register" << endl;
		return;
	}
	this->del_hard_breakpoint_by_slot(slot);	// Calling del_hard_breakpoint_by_slot to complete the job
}
void breakpoints::del_hard_breakpoint_by_slot(DWORD slot) {
	/*
	The function firsly checks if slot is in range 0 to 3 if it doesnt then we return and print that no such a slot exists
	Afterwards we turn off the bits indicating that this breakpoint exists in the DR7 reigster using AND, NOT, SHIFT bit wise operations
	*/
	if (slot < 0 || slot > 3) {
		cout << "Slot must be in range 0-3" << endl;
		return;
	}

	auto do_it = [&](DWORD tid) {
		/*
		This lambda function will run through all TIDs so all of the threads will delete their records of the breakpoint in DR7
		*/
		dbg->examine_registers(tid); // Updating the context structure of the debuggie

		dbg->context.Dr7 &= ~(0x3 << (slot * 2));		// 0x3 in bits is 11 so that L G bits are turn off using NOT and AND with SHIFT.
		dbg->context.Dr7 &= ~(0xf << (16 + slot * 4));	// 0xf in bits is 1111 so that the Lenght and Condition bits of the breakpoints will turn off

		dbg->modify_registers(tid, dbg->context);	// Applying the changes
	};
	dbg->enumerate_threads(do_it);		// Running the 'do_it' function for each thread related to our debugged process.
}


//Restoring memory bytes
bool breakpoints::restore_soft_break(LPCVOID addrs) {
	/*
	This function loops through all the breakpoints in the array,
	When the specified address is found it will write to that address the original byte and set the breakpoint active variable to false
	*/
	for (auto br : this->s_brs) {
		
		if (br.active && br.addrs == addrs) { // Checking if the breakpoint is active and the address its stores matches the address specified
			
			dbg->modify_memory((LPVOID)addrs, &br.original, 1);	// Writing the original byte
			br.active = false;														// Indicating the breakpoint is not in use
			cout << "Restored :D\n";												
				
			return true;															// Breaking out of the loop, not need to continue after the breakpoint is found
		}

	}

	return false;	// Indicating the breakpoint wasnt related to us
}

// Breakpoints hits hanlders

void breakpoints::soft_hit() {
	/*
	* aa bb 11
	* aa bb 11
	* 
	When a software breakpoint is hit the RIP is one instruction ahead of where it was needed to be, because it executed the 0xCC instruction;
	*/
	dbg->examine_registers(dbg->last_dbg_event.dwThreadId);	// Updating the context to the thread who hit the soft breakpoint
	dbg->context.Rip--;										// Decreasing RIP by 1 byte
	dbg->modify_registers(dbg->last_dbg_event.dwThreadId, dbg->context);	// Applying the new changes to the thread
}

// Printing stuff
void breakpoints::print_breakpoints() {
	/*
	This function prints all of the active soft breapoints
	*/
	
	cout << "Software breakpoints: " << endl;
	
	int c = 0; // This variable is tracking how many active breakpoints are found

	for (auto br : this->s_brs) { // Foreach loop on each breakpoint on the array
		
		if (br.active) {	// Checking if the breakpoing is active
			cout << c << ": " << br.addrs << endl;	// Printing its address and number
			c++;									// Incrementing c
		}

	}
	if (c == 0) {			// Checking if c=0, i.e no breakpoints are active
		cout << "None\n";	// printing "None"
	}
}