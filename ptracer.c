/* Kyle Plummer
 * ptracer.c
 * depends on pidlist.c
 * This program forks and executes one or more commands/programs passed as arguments.
 * This child process is traced and all syscalls are monitored. ptracer has the following signature:
 * ptracer [-f|-v OUTPUT FILE] command [args] ...
 * -f outputs to OUTPUT FILE in adition to stdout
 * -v gives additional verbose output to OUTPUT FILE (important registers on call and return)
 * command is a command or program executed exactly as though sent to command line
 * args are any command line arguments that would follow command
 *
 * ptracer utilizes ptrace() functionality to intercept and handle syscalls from a child process.
 * First the program sets up and prepares the input arguments
 * Next it forks off a child (tracee) process, where it attaches the trace and executes the given command
 * The parent (tracer) process meanwhile continues into the main trace loop where it waits for state
 * changes from the kernel, and handles them accordingly. Ptracer is awoken in the trace loop
 * by the kernel whenever the child (or a decendant?) has a state change. State changes occour when
 * the executing child initiates a syscall, receives a syscall return from kernel, or receives
 * another signal. When the tracer wakes it checks the signal info, syscall info, and grabs a snapshot of
 * the tracee's cpu registers. This data is stored in a linked list of traced processes. If the tracer
 * detects that the tracee in question already has an outstanding syscall, it assumes this is the return
 * and handles it by printing data about the syscall to stdout (and file output). After handling the
 * state change and signal/syscall info it resumes the tracee (which was halted by kernel for tracing).
 * Ptracer then continues to the top of the main loop and waits for the next tracee state change.
 *
 * See pidlist.c for info about the linked list and its support functions.
 */


/////////////////////////////
////// COMPILER MACROS //////
/////////////////////////////
#define _POSIX_C_SOURCE 199309L
//#define _POSIX_C_SOURCE 200809L

//////////////////////////
//////// INCLUDES ////////
//////////////////////////
#include <sys/signal.h>
//#include </usr/include/signal.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/stat.h>
//#include <sys/siginfo.h>
//#include <asm/siginfo.h>
//#include <linux/signal.h>
//#include <bits/siginfo.h>
#include "pidlist.h"

//////////////////////////
/////// Definitions //////
//////////////////////////
#define INFINITE_LOOP_GUARD	500
#define MAX_ARG_LEN		40
#define MAX_STRING_LEN		200
#define MAX_FILE_LEN		200



/////////////////////
/////// MAIN ////////
/////////////////////
int main (int argc, char **argv) {
	/*
	 * Here we take the command line arguments and set up the initial
	 * state of the program. We set the filename and output mode
	 * as well as prepare the structure that passes arguments to execve()
	*/

	int fileout = 0;
	char filename[MAX_FILE_LEN];


	//check if there are enough arguments
	if(argc < 2) {
		printf("Help: ptracer [-h] [-f file] command [args]\n");
		return 1;
	}


	//If arg 1 is -h print help text
	if(strcmp(argv[1], "-h") == 0) {
		printf("Help: ptracer [-h] [-f file] command [args]\n");
		return 0;
	}


	//If arg 1 is -f store filename and set fileout.
	if (strcmp(argv[1], "-f") == 0) {
		fileout = 1;
		strcpy(filename, argv[2]);
		if(argc < 4) {
			printf("Did you forget a filename or command? Use: ptracer [-h] [-f file] command [args]\n");
			return 1;
		}
	}


	//If arg 1 is -v store filename and set fileout for verbose
	if (strcmp(argv[1], "-v") == 0) {
		fileout = 2;
		strcpy(filename, argv[2]);
		if(argc < 4) {
                        printf("Did you forget a filename or command? Use: ptracer [-h] [-f file] command [args]\n");
                        return 1;
                }
	}


	//If fileout is set, ignore first 3 args (program, -f, filename)
	//If not, only ignore the first arg (programname)
	int n = (fileout > 0) ? 3 : 1;


	//Copy args from argv to args, a struct to get handed off to execve
	//ignore the first n arguments where n is 1, or 3 if file out is enabled
	char *args[argc + 1 - n];
	for(int z = n; z <= argc; z++) {
		args[z-n] = argv[z];
	}
	//Make sure the list is NULL terminated, required for execve()
	args[argc - n] = NULL;


	//print the argc list for debugging
	/*
	for(int i = 0; i <= argc - n; i++) {
		printf("%d: %s\n", i, args[i]);
	}
	*/


	//File for output if -f or -v is set
	FILE *file;
	if(fileout > 0) {
		file = fopen(filename, "w");

		//Check if fopen succeeded.
		int ferror = errno;
		if(file == NULL) {
			perror("Open file failed: ");
			return -1;
		}
	}




	//initialize pidlist, a linked list structure for storing information
	//about traced processes. See pidlist.h for more info.
	struct pidlist *pidlist = pidlist_init();


	/* Now we fork off a child process to be traced. After fork the value of child will
	 * be 0 for the child process, and the PID of that child for the parent process.
	 * both processes proceed from there and separate via the following if statement.
	 * The child process then executes the command given to the program with the args.
	 * The parent process continues from else and begins the main trace loop.
	*/
	int child = fork();
	if(child == 0) {
		//child process
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		//the following commented lines are remnants from an earlier attempt at getting grandchild processes to trace
		//ptrace(PTRACE_SETOPTIONS, getpid(), NULL, PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);
		//raise(SIGSTOP);
		execvp(args[0], args);
	}
	else {
		//ptrace(PTRACE_SETOPTIONS, getpid(), NULL, PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);

		//parent process - tracing
		//status will be updated by waitpid() and holds info about the state change that stopped the tracee
		int status;

		//add child to pidlist linked list. Then create a placeholder struct to avoid segfaults
		pidlist_add(child, pidlist);
		struct user_regs_struct dummy;

		//add the dummy struct to the linked list to avoid initial segfault
		pidlist_setregs(child, pidlist, &dummy);

		//this may get removed later, is a guard against infinite loops
		int infiniteloopguard = 0;


		/* Begin the main tracing loop. This will continue until all descendant processes have
		 * exited, or until the infinite loop guard reaches it's maximum, defined at the top.
		 * The loop follows this basic outline:
		 * -Break out if we have exceeded the INFINITE_LOOP_GUARD max number of loops.
		 * -Wait for signal from traced process.
		 * -Check if the signal indicates the process is terminated. If so, remove it from pidlist.
		 * -Get syscall info from ptrace with PTRACE_PEEKUSER, populating syscall with the syscall number
		 * -Check if the child is sending the syscall, or if the syscall is returning.
		 * -If the child is sending a syscall:
		 * 	-Store the syscall number in the corresponding pidlist node for later
		 * 	-Get the cpu registers with ptrace PTRACE_GETREGS
		 * 	-Then store the snapshot of registers in the corresponding pidlist node
		 * 	-If verbose file output is set, print verbose register info to file
		 * -If the syscall is returning to the child:
		 * 	-Reset the syscall number in the pidlist node
		 * 	-Prepare a second snapshot of cpu registers in case some were changed during syscall
		 * 	-If verbose file output is set, print verbose register info to file
		 * 	-Enter a switch to handle each of the 15 main syscalls, and a default for the rest
		 * 		-prepare, format, and output the data as necessary for each type of syscall
		 * -Tell the child to continue until the next syscall with ptrace PTRACE_SYSCALL
		 * -Continue looping...
		*/
		while(pidlist_isempty(pidlist) != 1) {

			//This guards against infinite loops, in case child processes mever end
			infiniteloopguard++;
			if(infiniteloopguard > INFINITE_LOOP_GUARD)
				break;

			//Here we wait. Kernel will wake this thread when a child process has a state change
			//and returns that child's PID into pid for identification.
			int pid = waitpid(-1, &status, 0);


			//if tracee status change was an exit, remove that child from pidlist
			if(WIFEXITED(status)) {
				pidlist_remove(pid, pidlist);
				//printf("DEBUG: PROCESS TERMINATED WIFEXITED(): %d\n", pid);
				continue;
			}

			//Handling additional signals - this is in progress still
			if(WIFSTOPPED(status)) {
				int signal = WSTOPSIG(status);
				/*
				if(signal == 17) {
					//printf("\nDEBUG: WIFSTOPPED pid = %d  -  signal = %d\n", pid, signal);
					//Signal 17 is SIGCHLD - notifying a child process has stopped or exited.
					//Can't get siginfo_t to work, so this hack is just to stop the program getting calls
					//and returns reversed and bugging out. Will probably introduce new bugs.
				}
				*/

				//siginfo_t struct holds info about signals
				siginfo_t siginfo;
				char string[MAX_STRING_LEN];
				switch(signal) {
					case 5:
						//We want to ignore signal 5 unless verbose output is on, this one is trace trap and comes up constantly
						ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo);
						if(fileout == 2) {
							fprintf(file, "Signal received by PID[%d]: si_signo = %d, si_errno = %d, si_code = %d, si_pid = %d, si_status = %d, si_value = %d\n",
								pid, siginfo.si_signo, siginfo.si_errno, siginfo.si_code, siginfo.si_pid,
								siginfo.si_status, siginfo.si_value
							);
						}
						break;

					case 17:
						//Signal 17 is SIGCHLD. This one restarts the trace and goes back to top of loop to fix a bug where
						//this signal caused the syscall out/in logic to get reversed. We would like to utilize the signal info better
						//but have nearly run out of time.
						ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo);
                                                sprintf(string, "%d]: si_signo = %d, si_errno = %d, si_code = %d, si_pid = %d, si_status = %d, si_value = %d\n",
                                                	pid, siginfo.si_signo, siginfo.si_errno, siginfo.si_code, siginfo.si_pid,
                                                        siginfo.si_status, siginfo.si_value
                                                );
						printf("Signal received by PID[%s", string);
                                                if(fileout > 0) {
							fprintf(file, "Signal received by PID[%s", string);
                                                }
						ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
						continue;

					default:
						//for all other signals, print to stdout and if file output is on, print to file as well
						ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo);
						//char s[MAX_STRING_LEN];
                                                sprintf(string, "%d]: si_signo = %d, si_errno = %d, si_code = %d, si_pid = %d, si_status = %d, si_value = %d\n",
                                                	siginfo.si_signo, siginfo.si_errno, siginfo.si_code, siginfo.si_pid,
                                                        siginfo.si_status, siginfo.si_value
                                                );
						printf("Signalreceived by PID[%s", string);
                                                if(fileout > 0) {
							fprintf(file, "Signal received by PID[%s", string);
                                                }
                                                break;
					}
				}



			//grab syscall ID from user data (found in ORIG_RAX register) the offset is multiplied by WORD length
			//which should be the same length as a long in any linux environment
			int syscall = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX, NULL);

			//Check the status of that PID in pidlist (pidlist_check returns the syscall value or -1)
			if(pidlist_check(pid, pidlist) == -1) {
				//tracee has placed a syscall
				//pidlist_setsys stores the syscall number for later
				pidlist_setsys(pid, syscall, pidlist);

				//Prepare a struct that holds values from the child's cpu registers
				//Then populate that struct with PTRACE_GETREGS and store it in pidlist for later
				struct user_regs_struct regs;
				ptrace(PTRACE_GETREGS, pid, NULL, &regs);
				pidlist_setregs(pid, pidlist, &regs);

				//If verbose file output is on, spit out as much register info as we can into the file
				if(fileout == 2) {
					fprintf(file, "VERBOSE: syscall [%ld] PID [%d]  %ld |  %ld | %ld | %ld | %ld | %ld | %ld | %ld | %ld\n",
						regs.orig_rax, pid, regs.rax, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9, regs.rbx, regs.rcx
					);
				}

			}
			else if(pidlist_check(pid, pidlist) >= 0) {
				//syscall result is returning to tracee
				//reset pidlist sys value, used for pidlist_check() elsewhere
				pidlist_setsys(pid, -1, pidlist);

				//grab the struct holding the snapshot of cpu registers from pidlist (populated when call was palced)
				//and grab the current state of cpu registers with PTRACE_GETREGS. Some regs may have changed during the call.
				struct user_regs_struct callregs;
				callregs = pidlist_getregs(pid, pidlist);
				struct user_regs_struct retregs;
				ptrace(PTRACE_GETREGS, pid, NULL, &retregs);


				//If verbose file output is on, spit out as much register info as we can into the file
				if(fileout == 2) {
					fprintf(file, "VERBOSE: syscall [%ld] PID [%d]  %ld |  %ld | %ld | %ld | %ld | %ld | %ld | %ld | %ld\n",
						retregs.orig_rax, pid, retregs.rax, retregs.rdi, retregs.rsi, retregs.rdx, retregs.r10, retregs.r8, retregs.r9, retregs.rbx, retregs.rcx
					);
				}



				/* The big switch. This switch has a handler for each of the 15 primary syscalls we are looking at
				 * with a default to print the main 6 registers and return value for all others.
				 * The primary registers for x86-x64 are: rdi, rsi, rdx, r10, r8, and r9. Orig_rax holds syscall value.
				 * It is alleged that rax holds the return value when the call comes back, but so far it remains elusive
				 */
				switch(syscall) {
					//These will be used to assemble the output
					char str[MAX_STRING_LEN];
					char tmp[MAX_ARG_LEN];

					case 0:   //read() syscall

						/* We build the strings using sprintf to print formatted characters
						 * to a temporary string, then we add tmp to str with strcat()
						 * for some reason if one printf's the resulting string it doesn't work
						 * unless you have some literal chars to add to the beginning, so
						 * we add the text "PID" that appears at the start until the very end.
						 * Once we have the string built, we print it. The same pattern will
						 * also be seen in the other cases below where needed.
						*/
						sprintf(str, "[%d]: read(%d \"", pid, callregs.rdi);
						for(int i = 0; i < callregs.rdx; i++) {
							char c = ptrace(PTRACE_PEEKDATA, pid, (callregs.rsi + i), NULL);
							switch(c) {
								case '\n':
									strcat(str, "\\n");
									break;
								case '\0':
									strcat(str, "\\0");
									break;
								case '\t':
									strcat(str, "\\t");
									break;
								case '\\':
									strcat(str, "\\");
									break;
								default:
									sprintf(tmp, "%c", c);
									strcat(str, tmp);
									break;
							}

							//truncate if too long...
							if(i > MAX_ARG_LEN) {
								sprintf(tmp, "... ");
								strcat(str, tmp);
								break;
							}
						}
						sprintf(tmp, "\", %d) = %d\n", callregs.rdx, retregs.rax);
						strcat(str, tmp);
						printf("PID%s", str); //oddly this prints nothing if there isnt some characters before the %s, so we add the beginning "PID" here.

						//If file out is enabled, also print to file.
						if(fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					case 1:   //write syscall
						sprintf(str, "[%d]: write(%d \"", pid, callregs.rdi);
						//printf("PID[%d]: write(%d \"", pid, callregs.rdi);
						for(int i = 0; i < callregs.rdx; i++) {
							char c = ptrace(PTRACE_PEEKDATA, pid, (callregs.rsi + i), NULL);
							switch(c) {
								case '\n':
									strcat(str, "\\n");
									break;
								case '\0':
									strcat(str, "\\0");
									break;
								case '\t':
									strcat(str, "\\t");
									break;
								case '\\':
									strcat(str, "\\");
									break;
								default:
									sprintf(tmp, "%c", c);
									strcat(str, tmp);
							}

							//truncate if too long...
							if(i > MAX_ARG_LEN) {
								strcat(str, "... ");
								break;
							}
						}
						sprintf(tmp, "\", %d) = %d\n", callregs.rdx, retregs.rax);
						strcat(str, tmp);
						printf("PID%s", str); //oddly this prints nothing if there isnt some characters before the %s, so we add the beginning "PID" here.

						//If file output is on, also print to file
						if(fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					case 2:   //open syscall
						sprintf(str, "[%d]: open(\"", pid);
						char c;
						for(int i = 0; i < 42; i++) {
							c = ptrace(PTRACE_PEEKDATA, pid, (callregs.rdi + i), NULL);
							if(c != '\0') {
								sprintf(tmp, "%c", c);
								strcat(str, tmp);
							}
							else {
								break;
							}

							//truncate if too long
							if(i > MAX_ARG_LEN){
								strcat(str, "...");
								break;
							}
						}
						sprintf(tmp, "\", %u) = %u\n", callregs.rsi, retregs.rax);
						strcat(str, tmp);
						printf("PID%s", str);  //oddly this prints nothing if there isnt some characters before the %s, so we add the beginning "PID" here.

						//if file output is on, also print to file
						if(fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					case 3:   //close syscall
						sprintf(str, "[%d]: close(%u) = %d\n", pid, callregs.rdi, retregs.rax);
						printf("PID%s", str);
						if (fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					case 5:   //fstat syscall
						sprintf(str, "[%d]: fstat(%u, st_mode=%d) = %d\n", pid, callregs.rdi, callregs.rsi, retregs.rax);
						printf("PID%s", str);
						if (fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					case 8:   //lseek syscall
						sprintf(str, "[%d]: lseek(%u, %d, %u) = %d\n", pid, callregs.rdi, callregs.rsi, callregs.rdx, retregs.rax);
						printf("PID%s", str);
						if (fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					case 22:  //pipe syscall
						sprintf(str, "[%d]: pipe(%d) = %d\n", pid, callregs.rdi, retregs.rax);
						printf("PID%s", str);
						if (fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					case 32:  //dup syscall
						sprintf(str, "[%d]: dup(%u) = %d\n", pid, callregs.rdi, retregs.rax);
						printf("PID%s", str);
						if (fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					case 33:  //dup2 syscall
						sprintf(str, "[%d]: dup2(%u, %u) = %d\n", pid, callregs.rdi, callregs.rsi, retregs.rax);
						printf("PID%s", str);
						if (fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					case 39:  //getpid syscall
						sprintf(str, "[%d]: getpid() = %d\n", pid, retregs.rax);
						printf("PID%s", str);
						if (fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					case 56:  //clone syscall
						sprintf(str, "[%d]: clone(%lu, %lu, %d, %d) = %d\n", pid, callregs.rdi, callregs.rsi, callregs.rdx, callregs.r10, retregs.rax);
						printf("PID%s", str);
						if (fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					case 57:  //fork syscall
						sprintf(str, "[%d]: fork() = %d\n", pid, retregs.rax);
						printf("PID%s", str);
						if (fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					case 59:  //execve syscall - should decode filename args if we get time
						sprintf(str, "[%d]: execve(%ld, %ld, %ld) = %d\n", pid, callregs.rdi, callregs.rsi, callregs.rdx, retregs.rax);
						printf("PID%s", str);
						if (fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					case 61:  //wait4 syscall
						sprintf(str, "[%d]: wait(%d, %d, %d, %d) = %d\n", pid, callregs.rdi, callregs.rsi, callregs.rdx, callregs.r10, retregs.rax);
						printf("PID%s", str);
						if (fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					case 231: //exit_group syscall
						sprintf(str, "[%d]: exit_group(%d) = %d\n", pid, callregs.rdi, retregs.rax);
						printf("PID%s", str);
						if (fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;

					default:
						sprintf(str, "[%d]: syscall[%d](%ld, %ld, %ld, %ld, %ld, %ld) = %d\n", pid, callregs.orig_rax, callregs.rdi, callregs.rsi, callregs.rdx, callregs.r10, callregs.r8, callregs.r9, retregs.rax);
						printf("PID%s", str);
						if (fileout > 0) {
							fprintf(file, "PID%s", str);
						}
						break;
				}

			}
			//Tell child process to resume. We will wait again at the top of the loop
			ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		}

	}

	//close the output file
	if(fileout > 0) {
		fclose(file);
	}

	//program exit success.
	return 0;
}

