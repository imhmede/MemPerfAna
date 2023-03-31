#include "pin.H"
#include "pinMarker.h"
#include <iostream>
#include <fstream>
#include <string.h>
#include <stdio.h>
#include <vector>
//#include<bits/stdc++.h>
using std::string;
using std::vector;
using std::pair;
using std::make_pair;

extern "C"
{
#include "backend.h"
}

//cache object for the load and store calls of the instrumentation functions
Cache* firstLevel;
Cache* lmsfirstLevel;
std::ofstream outFile;
vector< pair <long, int> > vectMiss;
vector< pair <long, int> > vectFreq;

//pin way of adding commandline parameters
//bool, if function calls are in the instrumented region or not
KNOB<bool> KnobFollowCalls(KNOB_MODE_WRITEONCE, "pintool", "follow_calls", "0", "specify if the instrumentation has to follow function calls between the markers. Default: false");
//path to the cache definition file
KNOB<std::string> KnobCacheFile(KNOB_MODE_WRITEONCE, "pintool", "cache_file", "cachedef", "specify if the file, where the cache object is defined. Default: \"cachedef\"");

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "memtrace.out", "specify dcache file name");
//KNOB< string > KnobMissFile(KNOB_MODE_WRITEONCE, "pintool", "o", "miss.out", "specify miss file name");
//KNOB< string > KnobFreqFile(KNOB_MODE_WRITEONCE, "pintool", "o", "freq.out", "specify frequancy file name");

//instruction and function addresses as markers for the instrumentation
ADDRINT startCall = 0;
ADDRINT startIns = 0;
ADDRINT stopCall = 0;
ADDRINT stopIns = 0;

// Driver function to sort the vector elements
// by second element of pairs
bool sortbysec(const pair<int,int> &a,
		const pair<int,int> &b)
{
	return (a.second < b.second);
}

//callback functions to activate and deactivate calls to the cache simulator on memory instructions. only needed when following function calls
VOID activate()
{
	std::cerr << "activate" << std::endl;
	_pinMarker_active = true;
}
VOID deactivate()
{
	std::cerr << "deactivate" << std::endl;
	_pinMarker_active = false;
}

//executed once. finds the magic pin marker functions and calls to them
VOID ImageLoad(IMG img, VOID *v)
{
	if (IMG_IsMainExecutable(img))
	{

		//find addresses of the start and stop function in the symbol table
		for( SYM sym= IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym) )
		{
			if (PIN_UndecorateSymbolName ( SYM_Name(sym), UNDECORATION_NAME_ONLY) == "_magic_pin_start")
			{
				startCall = SYM_Address(sym);
			}
			if (PIN_UndecorateSymbolName ( SYM_Name(sym), UNDECORATION_NAME_ONLY) == "_magic_pin_stop")
			{
				stopCall = SYM_Address(sym);
			}
		}

		if (startCall == 0 || stopCall == 0)
		{
			std::cerr << "Missing addresses for start and stop function!" << std::endl;
			exit(EXIT_FAILURE);
		}

		int startCallCtr = 0;
		int stopCallCtr = 0;
		//find call instructions to the start and stop functions and keep their instruction address
		for( SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) )
		{
			for( RTN rtn= SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn) )
			{
				RTN_Open(rtn);

				for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
				{
					if (INS_IsDirectControlFlow(ins))
					{
						if (INS_DirectControlFlowTargetAddress(ins) == startCall)
						{
							startCallCtr++;
							if (KnobFollowCalls)
							{
								// needed. activation and deactivation of the magic start and stop functions does not work
								const AFUNPTR Activate = (AFUNPTR) activate;
								INS_InsertPredicatedCall(ins, IPOINT_BEFORE, Activate, IARG_END);
							}
							else
							{
								startIns = INS_Address(ins);
							}
						}
						if (INS_DirectControlFlowTargetAddress(ins) == stopCall)
						{
							stopCallCtr++;
							if (KnobFollowCalls)
							{
								// needed. activation and deactivation of the magic start and stop functions does not work
								const AFUNPTR Deactivate = (AFUNPTR) deactivate;
								INS_InsertPredicatedCall(ins, IPOINT_BEFORE, Deactivate, IARG_END);
							}
							else
							{
								stopIns = INS_Address(ins);
							}
						}
					}
				}
				RTN_Close(rtn);
			}
		}

		if (startCallCtr > 1 || stopCallCtr > 1)
		{
			std::cerr << "Too many calls to start/stop functions found! Only one marked code region is supported." << std::endl;
			exit(EXIT_FAILURE);
		}
		else if (startCallCtr < 1 || stopCallCtr < 1)
		{
			std::cerr << "Not enough calls to start/stop functions found! Please mar a code region in the code." << std::endl;
			exit(EXIT_FAILURE);
		}
	}
}

//callbacks for loads and stores, containing check if current control flow is inside instrumented region (needed for following calls)
VOID MemRead_check(UINT64 addr, UINT32 size)
{
	if (_pinMarker_active)
		Cache__load(firstLevel, {static_cast<long int>(addr), size});
}
VOID MemWrite_check(UINT64 addr, UINT32 size)
{
	if (_pinMarker_active)
		Cache__store(firstLevel, {static_cast<long int>(addr), size},0);
}

//callbacks for loads and stores, without checks
VOID MemRead(UINT64 addr, UINT32 size)
{
	Cache__load(firstLevel, {static_cast<long int>(addr), size});
	outFile << "R " << addr << " " << size << std::endl;
}
VOID MemWrite(UINT64 addr, UINT32 size)
{
	Cache__store(firstLevel, {static_cast<long int>(addr), size},0);
	outFile << "W " << addr << " " << size << std::endl;
}

VOID _MemRead(UINT64 addr, UINT32 size)
{
	Cache__load(lmsfirstLevel, {static_cast<long int>(addr), size});
}
VOID _MemWrite(UINT64 addr, UINT32 size)
{
	Cache__store(lmsfirstLevel, {static_cast<long int>(addr), size},0);
}
// instrumentation routine inserting the callbacks to memory instructions
VOID Instruction(INS ins, VOID *v)
{
	// when following calls, each instruction has to be instrumented, containing a check if control flow is inside marked region
	// the magic start and stop functions set this flag
	/*if (KnobFollowCalls)
	  {
	  const AFUNPTR readFun = (AFUNPTR) MemRead_check;
	  const AFUNPTR writeFun = (AFUNPTR) MemWrite_check;

	  if (INS_IsMemoryRead(ins) && INS_IsStandardMemop(ins))
	  {
	  INS_InsertPredicatedCall(
	  ins, IPOINT_BEFORE, readFun,
	  IARG_MEMORYREAD_EA,
	  IARG_MEMORYREAD_SIZE,
	  IARG_END);
	  }

	  if(INS_IsMemoryWrite(ins))
	  {
	  INS_InsertPredicatedCall(
	  ins, IPOINT_BEFORE, writeFun,
	  IARG_MEMORYWRITE_EA,
	  IARG_MEMORYWRITE_SIZE,
	  IARG_END);
	  }
	  }*/

	// in case function calls do not need to be followed, only instructions inside the marked region need to be instrumented
	// this slightly decreases the overhead introduces by the pin callback
	//    else if(INS_Address(ins) > startIns && INS_Address(ins) < stopIns)
	//  {
	const AFUNPTR readFun = (AFUNPTR) MemRead;
	const AFUNPTR writeFun = (AFUNPTR) MemWrite;

	if (INS_IsMemoryRead(ins) && INS_IsStandardMemop(ins))
	{
		INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, readFun,
				IARG_MEMORYREAD_EA,
				IARG_MEMORYREAD_SIZE,
				IARG_END);
	}

	if(INS_IsMemoryWrite(ins))
	{
		INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, writeFun,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYWRITE_SIZE,
				IARG_END);
	}
	//}
}

// function to print the cache stats (needed, as the one from the cachesimulator does not work with pin)
VOID printStats(Cache* cache)
{
	std::cout << std::string(cache->name) << "\n";
	std::cout << "LOAD: " << cache->LOAD.count << " size: " << cache->LOAD.byte << " B\n";
	std::cout << "STORE: " << cache->STORE.count << " size: " << cache->STORE.byte << " B\n";
	std::cout << "HIT: " << cache->HIT.count << " size: " << cache->HIT.byte << " B\n";
	std::cout << "MISS: " << cache->MISS.count << " size: " << cache->MISS.byte << " B\n";
	std::cout << "EVICT: " << cache->EVICT.count << " size: " << cache->EVICT.byte << " B\n";
	std::cout << "\n";
	if (cache->load_from != NULL)
		printStats(cache->load_from);
}

// print stats, when instrumented program exits
VOID Fini(int code, VOID * v)
{
	std::ifstream infile;
	UINT64 addr;
	UINT32 size;
	char op = ' ';
	printStats(firstLevel);
	outFile.close();
	infile.open(KnobOutputFile.Value().c_str());
	while(infile >> op >> addr >> size)
	{
		if(op == 'R')
		{
			_MemRead(addr, size);
		}else
		{
			_MemWrite(addr, size);
		}
	}
	infile.close();
	printStats(lmsfirstLevel);
	//  printStats(lmsfirstLevel);

	long cl_id;
	int miss;
	int freq;
	int n = 0;

	printmiss();
	//infile.open(KnobMissFile.Value().c_str());
	infile.open("miss.out");
	while(infile >> cl_id >> miss)
	{
		vectMiss.push_back( make_pair(cl_id, miss) );
		n++;
	}
	infile.close();
	sort(vectMiss.begin(), vectMiss.end(), sortbysec);

	// Printing the sorted vector(after using sort())
	std::cout << "Report by Misses \n";
	for (int i=0; i < n; i++)
	{
		// "first" and "second" are used to access
		// 1st and 2nd element of pair respectively
		std::cout << vectMiss[i].first << " "
			<< vectMiss[i].second << std::endl;
	}
	printfreq();
	infile.open("freq.out");
	n = 0;
	while(infile >> cl_id >> freq)
	{
		vectFreq.push_back( make_pair(cl_id, freq) );
		n++;
	}
	infile.close();
	sort(vectFreq.begin(), vectFreq.end(), sortbysec);
	std::cout << "Report by Frequency\n";
	for (int i=0; i < n; i++)
	{
		// "first" and "second" are used to access
		// 1st and 2nd element of pair respectively
		std::cout << vectFreq[i].first << " "
			<< vectFreq[i].second << std::endl;
	}
	// not needed? and could break for more complicated cache configurations
	// dealloc_cacheSim(firstLevel);
}

int main(int argc, char *argv[])
{
	PIN_InitSymbols();

	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid 
	if( PIN_Init(argc,argv) )
	{
		return 1;
	}

	//get cachesim exits with failure on errors. in that case, the log file has to be checked
	firstLevel = get_cacheSim_from_file(KnobCacheFile.Value().c_str());
	lmsfirstLevel = get_cacheSim_from_file(KnobCacheFile.Value().c_str());

	if (KnobFollowCalls.Value())
	{
		std::cerr << "following of function calls enabled\n" << std::endl;
	}
	else
	{
		std::cerr << "following of function calls disabled\n" << std::endl;
	}

	outFile.open(KnobOutputFile.Value().c_str());
	//IMG_AddInstrumentFunction(ImageLoad, 0);
	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}
