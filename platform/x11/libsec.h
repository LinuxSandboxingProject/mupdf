#ifndef SECCOMP_H
#define SECCOMP_H

/* basic filter */
// this mode allows normal use
// only dangerous syscalls are blacklisted
int protectedMode(void);

/* secure read-only mode */
// whitelist minimal syscalls only
// this mode does not allow writing files
// or to open external links and applications
// network connections are prohibited as well
int protectedView(void);

#endif
