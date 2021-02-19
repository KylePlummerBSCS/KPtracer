# CSI402 - Final Project: Ptracer  

Click [here](https://youtu.be/veZtc4XD-bI) for a demo video on Youtube.

## Ptracer Detailed Description
This program forks and executes commands/programs passed as arguments. This child process is traced and all syscalls are monitored. ptracer has the following signature:  
  
  
`ptracer [-f | -v OUTPUT FILE] command [args] ...`  
  
  
-f outputs to OUTPUT FILE in adition to stdout  
-v gives additional verbose output to OUTPUT FILE (important registers on call and return)  

`Command` is a command or program executed exactly as though sent to command line. `Args` are any command line arguments that would follow command. Ptracer utilizes `ptrace()` functionality to intercept and handle syscalls from a child process. First the program sets up and prepares the input arguments. Next it forks off a child (tracee) process, where it attaches the trace and executes the given command
The parent (tracer) process, meanwhile, continues into the main trace loop where it waits for state changes from the kernel, and handles them accordingly. Ptracer is awoken in the trace loop by the kernel whenever the child has a state change. State changes occour when the executing child initiates a syscall, receives a syscall return from kernel, or receives another signal. When the tracer wakes it checks the signal info, syscall info, and grabs a snapshot of the tracee's cpu registers. This data is stored in a linked list of traced processes. If the tracer detects that the tracee in question already has an outstanding syscall, it assumes this is the return and handles it by printing data about the syscall to stdout (and file output). After handling the state change and signal/syscall info it resumes the tracee (which was halted by kernel for tracing). Ptracer then continues to the top of the main loop and waits for the next tracee state change.

pidlist is a linked-list structure for holding information about traced processes for use with ptracer.c. There are also a number of useful (and legacy) supporting functions. Supports initializatoin, adding and removing nodes, and updating and checking internal data. See ptracer.c for details.

Below we see the output when tracing a directory listing:
![Image of ptracer executing an ls -al](https://i.imgur.com/qNt3HsD.png)  

...  

![Completion of the trace on ls](https://i.imgur.com/TglTVDb.png)  
  
  
As the output is prepared and sent to stdout we can see the syscalls invoked in real time. The output file contains all the same information, but without the standard output visible:
![Output.txt excerpt](https://i.imgur.com/c7Tr0LJ.png)  

  
The verbose version of the file output has much more info and takes a bit of parsing to make sense of it.
![verbose output exceprt](https://i.imgur.com/CJbRlJQ.png)  
 
  
    

# Ptracer Manual

### **NAME**  
  
  Ptracer - trace system calls and signals



### **SYNOPSIS**  
  
  `ptracer [-f|-v OUTPUT FILE] COMMAND [ARGS] ...`



### **DESCRIPTION**  
  
  This program traces syscalls from, and signals to, a child process via ptrace(). Ptracer forks off a
  child process, attaches a trace, and executes given `COMMAND` with `ARGS`. The parent process meanwhile
  waits for signals from the kernal that the child has had a state change. State changes include receipt 
  of a signal, invocation of a syscall, or return from a syscall. When a state change is detected ptracer 
  handles the signal, and checks the state of the child's cpu registers. Pertinent info about the signals 
  and syscalls is printed to stdout, and to `FILE` if `-f` or `-v` are on. If `-v` is used the file output 
  is far more verbose with all important registers and signal info.
 

### **OPTIONS**  
  
  `-h`			Print help msg to standard output.
  
  `-f FILE`		Output to FILE as well as stdout. Mutually exclusive with -v.  
    
  `-v FILE`		Output to FILE as well as stdout. Output additional verbose info. Mutually exclusive
			with -f.  
			  
***  

# Research notes: (2019-11-16)
[Linux Syscall Reference](https://syscalls.kernelgrok.com/)

The first argument to ptrace is the command, which controls the behavior of the funciton call. To trace a process from inside that process (as when forking) use TRACEME

    ptrace(PTRACE_TRACEME, 0, NULL NULL) //parameters 2, 3, and 4 are ignored in this case.

In order to begin tracing a process remotely, call with PTRACE_ATTACH

    ptrace(PTRACE_ATTACH, pid, NULL, NULL) //pid is the process ID, parameters 3, and 4 are ignored.

Once tracing call wait() functions to wait for child processes to act. Waiting will end when traced process receives a signal.
May need to use waitid()? this fills in a struct with info including the PID, UID and more...
waitpid() returns the child PID that has changed state. See "RETURN VALUE" section in [man wait(2)](http://man7.org/linux/man-pages/man2/waitpid.2.html) 

PTRACE_PEEKUSER reads a word at offset from the USER area. Use the addr parameter (parameter 3) to specify an offset by referring to the register name as outlined in sys/reg.h. 
See the stackoverflow post [here](https://stackoverflow.com/questions/55048715/how-to-get-the-offset-of-a-given-cpu-register-in-rust) for some info on that offset.
It works like this: 

    int word = ptrace(PTRACE_PEEKUSER, pid, 8 * ORIG_RAX, NULL) 

Here pid is the child process we want to peek, and the offset is 8 * <REG NAME>. REG NAME will be ennumerated to an int value in reg.h, this is how far offset to find the value held by that
register in the user space. We multiply by 8 because each word is 8 bytes in a 64-bit environment so this offsets us by however many words gets us to the data we want.
Instead we can also use PTRACE_GETREGS which fills a struct passed in parameter 4 with all the general purpose registers. 

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

In the struct the registers can be referred to by name, like: int rbx_value = regs.rbx; For register names see the definition of the struct in [sys/user.h](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/x86/sys/user.h;h=02d3db78891a409c79571343cd732a9cdcdc868a;hb=eefa3be8e4c2c721a9f277d8ea2e11180231829f)
 
    main
        initialize stuff
        init list of child processes to track
        fork off a child process, attach the trace, and exec

        parent process waits for tracee, using wait() functions. ex. waitpid() will return execution when a specified child process changes state. (waitpid returns the PID of the process that changed state)
        execution resumes:
            if incoming signal - print details
            if outgoing syscall - print details & result
            if new process/fork attach trace to new process (PTRACE_ATTACH)
            if child terminates - update list of active children
            when all children are terminated - break out of handle signal loop
        loop back up to handle signal

        clean up and exit.


Some example [ptrace code](https://gist.github.com/willb/14488/80deaf4363ed408a562c53ab0e56d8833a34a8aa)

A [syscall table](https://filippo.io/linux-syscall-table/)

A [syscall reference](https://syscalls.kernelgrok.com/)

user_regs_struct defined in [sys/user.h](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/x86/sys/user.h;h=02d3db78891a409c79571343cd732a9cdcdc868a;hb=eefa3be8e4c2c721a9f277d8ea2e11180231829f)

Less than stellar [blog about ptrace](https://www.linuxjournal.com/article/6100)

man [ptrace](http://man7.org/linux/man-pages/man2/ptrace.2.html)

man [strace](http://man7.org/linux/man-pages/man1/strace.1.html)

man [wait](http://man7.org/linux/man-pages/man2/waitpid.2.html)

syscall values can be found in /usr/include/x86_64-linux-gnu/asm/unistd_64.h


