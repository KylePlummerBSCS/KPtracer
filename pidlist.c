/* Kyle Plummer, Mounika Gogula, James Schallert
 *
 * pidlist is a linked-list structure for holding information about traced processes
 * for use with ptracer.c. There are also a number of useful (and legacy) supporting
 * functions. Supports initializatoin, adding and removing nodes, and updating and
 * checking internal data.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <sys/reg.h>




// pidlist structure - linked list
// elements:
// 	int pid  		process id of traced thread
//	int sys  		syscal num, -1 means not in syscall
//	char *str 		string, no longer used?
//	struct user_...	*regs	pointer to structure holding info about cpu registers
//	struct pidlist *next	pointer to next node in linkedlist
struct pidlist
{
	int pid;
	int sys;
	//char *str;
	struct user_regs_struct *regs;
	struct pidlist *next;
};





// pidlist_init()
// initilization/construction - initializes a pidlist and returns a pointer
// to it. Must be called before any other functions.
struct pidlist* pidlist_init() {
	struct pidlist *list = malloc(sizeof(struct pidlist));
	list->pid = -1;
	list->sys = -1;
	list->regs = NULL;
	list->next = NULL;
	return list;
}




// pidlist_add()
// add new node to linked list
// args:
//	pid		the process ID to add
//	*list		pointer to pidlist head
void pidlist_add(int pid, struct pidlist *list) {
	struct pidlist *current = list;
	while(current->pid != -1) {
		current = current->next;
	}
	struct pidlist *node = malloc(sizeof(struct pidlist));
	current->pid = pid;
	current->sys = 1;//start with 1, as tracee clone begins mid-syscall?
	node->pid = -1;
	node->sys = -1;
	node->next = NULL;
	node->regs = NULL;
	current->next = node;
	return;
}




// pidlist_remove()
// removes a pid from the list
// args:
//	int pid		the process ID to remove from list
//	pidlist *list	pointer to pidlist head
void pidlist_remove(int pid, struct pidlist *list) {
	struct pidlist *current, *prev;
	if(list->pid == pid) {
		*list = *(list->next);
		return;
	}

	prev = list;
	current = prev->next;
	while(current->pid != -1) {
		if(current->pid == pid) {
			prev->next = current->next;
			return;
		}
		prev = current;
		current = current->next;
	}
}




// pidlist_check()
// Checks status of syscall element for pid
// args:
//	int pid		the process ID to check
//	pidlist *list	pointer to pidlist head
// return:
//	int		syscall num previously saved
int pidlist_check(int pid, struct pidlist *list) {
	struct pidlist *current = list;
	while(current->pid != -1) {
		if(current->pid == pid) {
			return current->sys;
		}
	current = current->next;
	}
}




// pidlist_toggle()
// Toggles sys flag between 1 and 0 for pid
// This legacy function has been replaced by setsys() and check(),
// instead of checking this flag, we just check the syscall num
// with -1 indicating not in syscall
// args:
//	int pid		the prpcess ID whos flag gets toggled
//	pidlist *list	pointer to pidlist head
/*
void pidlist_toggle(int pid, struct pidlist *list) {
	struct pidlist *current = list;
	while(current->pid != -1) {
		if(current->pid == pid) {
			current->sys = (current->sys == 0) ? 1 : 0;
		}
		current = current->next;
	}
}
*/




// pidlist_setsys()
// Sets the syscall value for pid. Replaces toggle() for checking
// status of syscall. Int sys holds the syscall value or -1.
// args:
//	int pid		the process id of tracee
//	int sys		the syscall value (or -1)
//	pidlist *list	pointer to list head
void pidlist_setsys(int pid, int sys, struct pidlist *list) {
	struct pidlist *current = list;
	while(current->pid != -1) {
		if(current->pid == pid) {
			current->sys = sys;
		}
		current = current->next;
	}
}




// pidlist_isempty()
// Checks if list is empty (head is null node)
// args:
//	pidlist *list	pointer to head of list
// return:
// 	int		bool: 1 for empty, 0 for non-empty
int pidlist_isempty(struct pidlist *list) {
	if(list->pid == -1)
		return 1;
	else
		return 0;
}



// pidlist_print()
// prints each pid and its sys state for debugging.
// args:	pidlist *list	pointer to head of list
/*
void pidlist_print(struct pidlist *list) {
	struct pidlist *current = list;
	while(current->pid != -1) {
		printf("%d [%d]\n", current->pid, current->sys);
		current = current->next;
	}
}
*/



// pidlist_getregs()
// gets a struct holding cpu register information for saved by setregs()
// args:
//	int pid			pid of process who's registers we want
//	pidlist *list		pointer to head of list
// return:
//	struct user_regs_struct	struct holding the cpu register data
struct user_regs_struct pidlist_getregs(int pid, struct pidlist *list) {
	struct pidlist *current = list;
        while(current->pid != -1) {
                if(current->pid == pid) {
			return *(current->regs);
                }
                current = current->next;
        }
}



// pidlist_setregs()
// saves the snapshot of cpu registers in a struct for later retrival with getregs()
// args:
//	int pid			pid of process whos registers are to be saved
//	pidlist *list		pointer to head of list
//	struct user_r... *regs	structure holding the cpu regster data to be saved
void pidlist_setregs(int pid, struct pidlist *list, struct user_regs_struct *regs) {
	struct pidlist *current = list;
        while(current->pid != -1) {
                if(current->pid == pid) {
                        current->regs = regs;
                }
                current = current->next;
        }
}
