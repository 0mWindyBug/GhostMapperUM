## GhostMapperUM
manual map your unsigned driver over signed memory 

inspired by the initial research and PoC (https://github.com/Oliver-1-1/GhostMapper) made by @Oliver-1-1 :) 

since the original PoC intended to mainly demonstrate the concept , Oliver chose to use a driver to map another unsigned driver 
GhostMapperUM intends to provide a more realistic / "ready to use" version of GhostMapper , implementing it entirely from usermode

generally speaking , we do that by exploiting the iqvw64e.sys vulnerable intel driver (thanks to kdmapper's utilities - https://github.com/TheCruZ/kdmapper) 

## Usage 
set the path your your target driver in 'config.h' and compile 

just run GhostMapperUM.exe 

note your driver should not touch the DriverObject / RegistryPath entry args since we pass NULL there 

## dump drivers 
You should read the detailed readme description in the original GhostMapper repo , in short : 

when a crush happens ,  crush related data needs to be saved to disk. 
drivers that need to save data to disk on a crush are cloned with the prefix of 'dump_' 

the idea behind this is that on a crush , the system is in an unknwon state , a driver that needs to save data to disk might be the one that caused the crush...
to solve that , the kernel asks the clones to step in and write the data instead 

and that's why , by design , after initialization , dump drivers are kept in a suspended state and are not in use (to minimize the chance they will be corrupted in case of a crush) 

this gives us the opportuinty to leverage the signed memory range held by those 'ghost' drivers and map our own driver over it !  

## the mapping procedure 
* Read the specefied driver in 'config.h' from disk , that is the unsigned driver to map 
* Find the base address of a ghost driver (we target dump_dumpfve.sys)
* apply relocations to our local target driver image & fix imports
* mark the entire ghost driver range as rwx by directly manipulating ptes through iqvw64e.sys's read/write primitive (saving the original ptes in a vector) 
* read the original ghost driver image
* write our target driver over the ghost driver using a standard write primitive (no need for write to readonly...) 
* to avoid rwx pages we unset the 'rw' bit from executable sections pages ptes , and set the 'nx' bit for others 
* finally , we call the entry point of the mapped driver by patching  ZwAddAtom to jump to it , and calling NtAddAtom to trigger the syscall
* when your driver is sone (sync this somehow...) call the RestoreOriginalDriver function to restore the original ghost driver image and ptes like we never patched it (currently it's' called after returning from DriverEntry since the example driver we map does nothing afterwards, oviously change that according to your needs )
* cleaning of traces taken from kdmapper 

## trivial detection vectors and things to consider 
* whilst the mapped driver is active , the ghost driver's text section on disk differs from the one in memory
* whilst the mapped driver is active , section's memory protections differ between disk and memory
* saying that , the image path of dump drivers is not a valid path on disk , some anti cheats (and perhaps AVs) tend to skip them during integrity checks, some arent , check it for your specific use-case

