#include "libsec.h"
#include <stdio.h>

#define HAVE_LIBSECCOMP
#ifdef HAVE_LIBSECCOMP

#include <seccomp.h> /* libseccomp */
#include <sys/prctl.h> /* prctl */
#include <sys/socket.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>

#define DENY_RULE(call) { if (seccomp_rule_add (ctx, SCMP_ACT_KILL, SCMP_SYS(call), 0) < 0) goto out; }
#define ALLOW_RULE(call) { if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(call), 0) < 0) goto out; }

scmp_filter_ctx ctx;


int protectedMode(void){

    // prevent child processes from getting more priv e.g. via setuid, capabilities, ...
    //prctl(PR_SET_NO_NEW_PRIVS, 1);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl SET_NO_NEW_PRIVS");
        exit(EXIT_FAILURE);
    }


    // prevent escape via ptrace
    //prctl(PR_SET_DUMPABLE, 0);

    if(prctl (PR_SET_DUMPABLE, 0, 0, 0, 0)){
        perror("prctl PR_SET_DUMPABLE");
        exit(EXIT_FAILURE);
    }


    // initialize the filter
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL)
        return 1;

    DENY_RULE (_sysctl);
    DENY_RULE (acct);
    DENY_RULE (add_key);
    DENY_RULE (adjtimex);
    DENY_RULE (chroot);
    DENY_RULE (clock_adjtime);
    DENY_RULE (create_module);
    DENY_RULE (delete_module);
    DENY_RULE (fanotify_init);
    DENY_RULE (finit_module);
    DENY_RULE (get_kernel_syms);
    DENY_RULE (get_mempolicy);
    DENY_RULE (init_module);
    DENY_RULE (io_cancel);
    DENY_RULE (io_destroy);
    DENY_RULE (io_getevents);
    DENY_RULE (io_setup);
    DENY_RULE (io_submit);
    DENY_RULE (ioperm);
    DENY_RULE (iopl);
    DENY_RULE (ioprio_set);
    DENY_RULE (kcmp);
    DENY_RULE (kexec_file_load);
    DENY_RULE (kexec_load);
    DENY_RULE (keyctl);
    DENY_RULE (lookup_dcookie);
    DENY_RULE (mbind);
    DENY_RULE (nfsservctl);
    DENY_RULE (migrate_pages);
    DENY_RULE (modify_ldt);
    DENY_RULE (mount);
    DENY_RULE (move_pages);
    DENY_RULE (name_to_handle_at);
    DENY_RULE (open_by_handle_at);
    DENY_RULE (perf_event_open);
    DENY_RULE (pivot_root);
    DENY_RULE (process_vm_readv);
    DENY_RULE (process_vm_writev);
    DENY_RULE (ptrace);
    DENY_RULE (reboot);
    DENY_RULE (remap_file_pages);
    DENY_RULE (request_key);
    DENY_RULE (set_mempolicy);
    DENY_RULE (swapoff);
    DENY_RULE (swapon);
    DENY_RULE (sysfs);
    DENY_RULE (syslog);
    DENY_RULE (tuxcall);
    DENY_RULE (umount2);
    DENY_RULE (uselib);
    DENY_RULE (vmsplice);

    //applying filter...
    if (seccomp_load (ctx) >= 0){
	// free ctx after the filter has been loaded into the kernel
	seccomp_release(ctx);
        return 0;
    }
    
  out:
    //something went wrong
    //printf("something went wrong\n");
    seccomp_release(ctx);
    return 1;
}


int protectedView(void){

    // prevent child processes from getting more priv e.g. via setuid, capabilities, ...
    //prctl(PR_SET_NO_NEW_PRIVS, 1);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl SET_NO_NEW_PRIVS");
        exit(EXIT_FAILURE);
    }


    // prevent escape via ptrace
    //prctl(PR_SET_DUMPABLE, 0);

    if(prctl (PR_SET_DUMPABLE, 0, 0, 0, 0)){
        perror("prctl PR_SET_DUMPABLE");
        exit(EXIT_FAILURE);
    }

    
    // initialize the filter
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL)
        return 1;


    ALLOW_RULE (access);
    ALLOW_RULE (brk);
    ALLOW_RULE (clock_gettime);
    ALLOW_RULE (close);
    ALLOW_RULE (connect);
    ALLOW_RULE (exit);
    ALLOW_RULE (exit_group);
    ALLOW_RULE (fcntl);  /* not specified below */
    ALLOW_RULE (fstat);
    ALLOW_RULE (futex);
    ALLOW_RULE (getpeername);
    ALLOW_RULE (getrlimit);
    ALLOW_RULE (getsockname);
    ALLOW_RULE (getsockopt);  /* needed for access to x11 socket in network namespace (without abstract sockets) */
    ALLOW_RULE (lseek);
    ALLOW_RULE (mmap);
    ALLOW_RULE (mprotect);
    ALLOW_RULE (mremap);
    ALLOW_RULE (munmap);
    //ALLOW_RULE (open);  /* specified below */
    ALLOW_RULE (prctl);
    ALLOW_RULE (poll);
    ALLOW_RULE (read);
    ALLOW_RULE (recvfrom);
    ALLOW_RULE (recvmsg);
    ALLOW_RULE (restart_syscall);
    ALLOW_RULE (rt_sigaction);
    ALLOW_RULE (seccomp);
    ALLOW_RULE (select);
    ALLOW_RULE (shmat);
    ALLOW_RULE (shmctl);
    ALLOW_RULE (shmget);
    ALLOW_RULE (shutdown);
    ALLOW_RULE (stat);
    //ALLOW_RULE (socket);  /* specified below */
    ALLOW_RULE (sysinfo);
    ALLOW_RULE (uname);
    //ALLOW_RULE (write);  /* specified below */
    ALLOW_RULE (writev);  /* not specified below */
    ALLOW_RULE (wait4);  /* trying to open links should not crash the app */

    
	/* special restrictions for socket, only allow AF_UNIX/AF_LOCAL */
	if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1,
	                      SCMP_CMP(0, SCMP_CMP_EQ, AF_UNIX)) < 0)
		goto out;

	if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1,
	                      SCMP_CMP(0, SCMP_CMP_EQ, AF_LOCAL)) < 0)
		goto out;


	/* special restrictions for open, prevent opening files for writing */
	if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
	                      SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY | O_RDWR, 0)) < 0)
		goto out;

	if (seccomp_rule_add (ctx, SCMP_ACT_ERRNO (EACCES), SCMP_SYS(open), 1,
	                      SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY)) < 0)
		goto out;

	if (seccomp_rule_add (ctx, SCMP_ACT_ERRNO (EACCES), SCMP_SYS(open), 1,
	                      SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR)) < 0)
		goto out;





    // ------------ experimental filters ---------------




    /* this filter is susceptible to TOCTOU race conditions, providing limited use */
    /* allow opening only specified files identified by their file descriptors*/

    // this requires either a list of all files to open (A LOT!!!)
    // or needs to be applied only after initialisation, right before parsing
    // if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
    //                         SCMP_CMP(SCMP_CMP_EQ, fd)) < 0) // or < 1 ???
    //     goto out;


    /* restricting write access */

    /* allow stdin */
    // if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
    //                         SCMP_CMP(0, SCMP_CMP_EQ, 0)) < 0 )
    //     goto out;

    /* allow stdout */
    // if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
    //                             SCMP_CMP(0, SCMP_CMP_EQ, 1)) < 0 )
    //     goto out;

    /* allow stderr */
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
                                 SCMP_CMP(0, SCMP_CMP_EQ, 2)) < 0 )
        goto out;


    /* restrict writev (write a vector) access */
    // this does not seem reliable but it surprisingly is. investigate more
    //if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 1,
    //                            SCMP_CMP(0, SCMP_CMP_EQ, 3)) < 0 )
    //    goto out;

    //test if repeating this after some time or denying it works


    // firest attempt to filter poll requests
    // if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 1,
    // 	                      SCMP_CMP(0, SCMP_CMP_MASKED_EQ, POLLIN | POLL, 0)) < 0)
    // 	goto out;


    /* restrict fcntl calls */
    // this syscall sets the file descriptor to read write
    //if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 1,
    //                            SCMP_CMP(0, SCMP_CMP_EQ, 3)) < 0 )
    //    goto out;
    // fcntl(3, F_GETFL)                       = 0x2 (flags O_RDWR)
    // fcntl(3, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
    // fcntl(3, F_SETFD, FD_CLOEXEC)           = 0




    // ------------------ end of experimental filters ------------------

    //applying filter...
    if (seccomp_load (ctx) >= 0){
	// free ctx after the filter has been loaded into the kernel
	seccomp_release(ctx);
        return 0;
    }

 out:
    //something went wrong
    seccomp_release(ctx);
    return 1;
}

int renderFilter(void){

    // prevent child processes from getting more priv e.g. via setuid, capabilities, ...
    //prctl(PR_SET_NO_NEW_PRIVS, 1);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl SET_NO_NEW_PRIVS");
        exit(EXIT_FAILURE);
    }


    // prevent escape via ptrace
    //prctl(PR_SET_DUMPABLE, 0);

    if(prctl (PR_SET_DUMPABLE, 0, 0, 0, 0)){
        perror("prctl PR_SET_DUMPABLE");
        exit(EXIT_FAILURE);
    }

    
    // initialize the filter
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL)
        return 1;


    ALLOW_RULE (access);
    ALLOW_RULE (brk);
    ALLOW_RULE (clock_gettime);
    ALLOW_RULE (close);
    //ALLOW_RULE (connect);
    ALLOW_RULE (exit);
    ALLOW_RULE (exit_group);
    ALLOW_RULE (fcntl);  /* not specified below */
    ALLOW_RULE (fstat);
    ALLOW_RULE (futex);
    ALLOW_RULE (getpeername);
    ALLOW_RULE (getrlimit);
    //ALLOW_RULE (getsockname);
    //ALLOW_RULE (getsockopt); 
    ALLOW_RULE (lseek);
    ALLOW_RULE (mmap);
    ALLOW_RULE (mprotect);
    ALLOW_RULE (mremap);
    ALLOW_RULE (munmap);
    //ALLOW_RULE (open);  /* specified below */
    ALLOW_RULE (poll);
    ALLOW_RULE (read);
    ALLOW_RULE (recvfrom);
    ALLOW_RULE (recvmsg);
    ALLOW_RULE (restart_syscall);
    ALLOW_RULE (rt_sigaction);
    ALLOW_RULE (select);
    ALLOW_RULE (shmat);
    ALLOW_RULE (shmctl);
    ALLOW_RULE (shmget);
    ALLOW_RULE (shutdown);
    ALLOW_RULE (stat);
    //ALLOW_RULE (socket);
    ALLOW_RULE (sysinfo);
    ALLOW_RULE (uname);
    //ALLOW_RULE (write);  /* specified below */
    ALLOW_RULE (writev);  /* not specified below */
    ALLOW_RULE (wait4);  /* trying to open links should not crash the app */

    
	/* special restrictions for socket, only allow AF_UNIX/AF_LOCAL */
    //	if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1,
    //	                      SCMP_CMP(0, SCMP_CMP_EQ, AF_UNIX)) < 0)
    //		goto out;

    //	if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1,
    //	                      SCMP_CMP(0, SCMP_CMP_EQ, AF_LOCAL)) < 0)
    //		goto out;


	/* special restrictions for open, prevent opening files for writing */
	if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
	                      SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY | O_RDWR, 0)) < 0)
		goto out;

	if (seccomp_rule_add (ctx, SCMP_ACT_ERRNO (EACCES), SCMP_SYS(open), 1,
	                      SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY)) < 0)
		goto out;

	if (seccomp_rule_add (ctx, SCMP_ACT_ERRNO (EACCES), SCMP_SYS(open), 1,
	                      SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR)) < 0)
		goto out;





    // ------------ experimental filters ---------------




    /* this filter is susceptible to TOCTOU race conditions, providing limited use */
    /* allow opening only specified files identified by their file descriptors*/

    // this requires either a list of all files to open (A LOT!!!)
    // or needs to be applied only after initialisation, right before parsing
    // if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
    //                         SCMP_CMP(SCMP_CMP_EQ, fd)) < 0) // or < 1 ???
    //     goto out;


    /* restricting write access */

    /* allow stdin */
    // if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
    //                         SCMP_CMP(0, SCMP_CMP_EQ, 0)) < 0 )
    //     goto out;

    /* allow stdout */
    // if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
    //                             SCMP_CMP(0, SCMP_CMP_EQ, 1)) < 0 )
    //     goto out;

    /* allow stderr */
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
                                 SCMP_CMP(0, SCMP_CMP_EQ, 2)) < 0 )
        goto out;


    /* restrict writev (write a vector) access */
    // this does not seem reliable but it surprisingly is. investigate more
    //if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 1,
    //                            SCMP_CMP(0, SCMP_CMP_EQ, 3)) < 0 )
    //    goto out;

    //test if repeating this after some time or denying it works


    // firest attempt to filter poll requests
    // if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 1,
    // 	                      SCMP_CMP(0, SCMP_CMP_MASKED_EQ, POLLIN | POLL, 0)) < 0)
    // 	goto out;


    /* restrict fcntl calls */
    // this syscall sets the file descriptor to read write
    //if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 1,
    //                            SCMP_CMP(0, SCMP_CMP_EQ, 3)) < 0 )
    //    goto out;
    // fcntl(3, F_GETFL)                       = 0x2 (flags O_RDWR)
    // fcntl(3, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
    // fcntl(3, F_SETFD, FD_CLOEXEC)           = 0




    // ------------------ end of experimental filters ------------------

    //applying filter...
    if (seccomp_load (ctx) >= 0){
	// free ctx after the filter has been loaded into the kernel
	seccomp_release(ctx);
        return 0;
    }

 out:
    //something went wrong
    seccomp_release(ctx);
    return 1;
}


#else /* HAVE_LIBSECCOMP */


int protectedMode(void){

    perror("No seccomp support compiled-in\n");
    return 1;
}

int protectedView(void){

    perror("No seccomp support compiled-in\n");
    return 1;
}

int renderFilter(void){

    perror("No seccomp support compiled-in\n");
    return 1;
}

#endif /* HAVE_LIBSECCOMP */
