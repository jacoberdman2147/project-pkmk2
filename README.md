# project-pkmk2
Originally started as a quick program to kill processes through the systematic corruption of their memory, now has more functionality to test the boundaries of what potentially malicious actions a program can and cannot do

It's essentially a barebones command line which can be used to run a few functions I have created. The purpose of these was to see what I could use and misuse within windows using pinvoke to get lower level functions and call them from C# code.

To view the commands, type in "cmds". The way I dealt with commands and their arguments was simple but quick.

# Command list:
* freeze, takes a string argument representing the process to freeze, does exactly what you would expect. It freezes whatever process you have targeted.

* resume, takes a string argument representing the process to resume, resumes a frozen process

* threadterm, takes a string argument representing the process to target, kills a process by terminating individual threads of that process

* procterm, takes a string argument representing the process to target, just kills a process in the ordinary, standard way

* threadinfo, takes a string argument representing the process to target, returns that statuses of the threads for the given process

* memkill, takes a string argument representing the process to target, the star of the program. This program grabs all read/writable memory regions within a running process and slowly fills them with garbage data, which always represents in a crash of the process, or potentially some unexpected behavior

* shake, takes a string argument representing the process to target, will shake a given window randomly. Be ready to terminate its process.

* listproc, no arguments, will list all the running processes on the system that the program has access to

* memkillrandom, no arguments, **DO NOT RUN THIS ON YOUR SYSTEM** This command will target processes randomly and run the memkill function on them. This can and will crash your system with some very very unexpected behavior. Will ask for a confirmation

* lasterror, no arguments, pretty much just a debug function when something goes wrong

* exit, no arguments, exits the program

* blockinput, no arguments, did you know you can completely disable all input from the mouse and keyboard? I believe this requires administrator privileges. To regain input, use ctrl + alt + delete

* swapbuttons, no arguments, did you know you can also swap the mouse buttons? I've never seen a malicious use of this and I am quite surprised with all the malware samples I have

* beep, no arguments, the console beeps. A lot.

* beepswap, no arguments, this is just annoying, don't run this.

# Todo:
* Implement a better system for handling commands and their arguments
* Implement a standardized way to get info within the program about specific functions
* Find more interesting things to do
