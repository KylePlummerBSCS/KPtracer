//pidlist.h - see pidlist.c for more info
//signatures for pidlist functions:
struct pidlist* pidlist_init();
void pidlist_add(int pid, struct pidlist *list);
void pidlist_remove(int pid, struct pidlist *list);
int pidlist_check(int pid, struct pidlist *list);
void pidlist_toggle(int pid, struct pidlist *list);
void pidlist_setsys(int pid, int sys, struct pidlist *list);
int pidlist_isempty(struct pidlist *list);
void pidlist_print(struct pidlist *list);
struct user_regs_struct pidlist_getregs(int pid, struct pidlist *list);
void pidlist_setregs(int pid, struct pidlist *list, struct user_regs_struct *regs);
