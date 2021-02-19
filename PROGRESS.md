# Progress Report 2019-12-04

## Team Name: Group 5
* [@kplumme1](https://github.com/kplumme1) - Kyle Plummer
* [@JamesSchallert](https://github.com/JamesSchallert) - James Schallert
* [@mgogula](https://github.com/mgogula) - Mounika Gogula


We have implemented syscall tracing and signal tracing as best we could. Unfortunately we ran out of time before we could reach our completed vision for this program.
Currently syscalls tell us the most, with signal tracing being very rudimentary. We wanted to also trace all descendant processes beyond the first child, but require
a bit more time to utilize SIGCHLD and PTRACE_ATTACH. The functionality to track multiple processes is there, but we don;t do much with it. 

Group Member | Tasks Assigned | tasks performed | Contribution
------------ | -------------- | --------------- | ------------
@kplumme1 | release demo | brainstorming, research, setup, extensive coding, inline documentation | 40%
@JamesSchallert | release demo | brainstorming, research, setup, coding, documentation | 30%
@mgogula | release demo| brainstorming, setup, research, coding, demo video | 30%









# Progress Report 2019-11-08

## Team Name: Group 5
* [@kplumme1](https://github.com/kplumme1) - Kyle Plummer
* [@JamesSchallert](https://github.com/JamesSchallert) - James Schallert
* [@mgogula](https://github.com/mgogula) - Mounika Gogula

So far we have created the github repo and set up empty files to fill in as we progress. We have met and worked on an outline for our project. We are currently identifying and delegating tasks. 
Phase 2, where we code implementation, is ready to move foreward. The basic outline of the trace program follows:

    main
        initialize stuff
        init list of child processes to track
        fork off a child process, attach the trace, and exec
        
        parent process waits for signal from tracee
        handle signal:
            if incoming signal - print details
            if outgoing syscall - print details & result
            if new process/fork attach trace to new process (PTRACE_ATTACH)
            if child terminates - update list of active children
            when all children are terminated - break out of handle signal loop
        loop back up to handle signal
        
        clean up and exit.


Group Member | Tasks Assigned | tasks performed | Contribution
------------ | -------------- | --------------- | ------------
@kplumme1 | progress report | brainstorming, setup | 34%
@JamesSchallert | research | brainstorming, setup | 33%
@mgogula | research | brainstorming, setup | 33%


