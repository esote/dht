#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "dhtd.h"

struct proc {
	char *title;
	int (*start)(void);
	const char *root;
};

void usage(void);
const struct proc *proc_search(const char *s, const struct proc *procs, size_t nprocs);
void proc_init(const char *root);
void proc_exec(char *progname, int fds[DHTD_NUMPROC]);

const struct proc procs[] = {
	{ "listen", listen_start, LISTEN_ROOT },
	{ "rtable", rtable_start, RTABLE_ROOT }
};

int
main(int argc, char *argv[])
{
	int c;
	const struct proc *proc = NULL;
	int fds[DHTD_NUMPROC];

	while ((c = getopt(argc, argv, "P:")) != -1) {
		switch (c) {
		case 'P':
			if ((proc = proc_search(optarg, procs, nitems(procs))) == NULL) {
				errx(1, "invalid process title %s", optarg);
			}
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	if (argc > 0) {
		usage();
	}

	if (proc == NULL) {
		proc_exec(argv[0], fds);
		proc_init(PARENT_ROOT);
		return parent_start(fds);
	}

	proc_init(proc->root);
	return proc->start();
}

void
usage(void)
{
	exit(1);
}

const struct proc *
proc_search(const char *s, const struct proc *procs, size_t nprocs)
{
	size_t i;
	for (i = 0; i < nprocs; i++) {
		if (strcmp(s, procs[i].title) == 0) {
			return &procs[i];
		}
	}
	return NULL;
}

void
proc_init(const char *root)
{
	struct passwd *pw;

	if ((pw = getpwnam(DHTD_USER)) == NULL) {
		if (errno == 0) {
			errx(1, "getpwnam");
		} else {
			err(1, "getpwnam");
		}
	}

	if (chroot(root) == -1) {
		err(1, "chroot %s", root);
	}
	if (chdir("/") == -1) {
		err(1, "chdir '/'");
	}

	/* TODO: setproctitle */

	if (setgroups(1, &pw->pw_gid) == -1) {
		err(1, "setgroups %u", pw->pw_gid);
	}
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
		err(1, "setresgid %u", pw->pw_gid);
	}
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
		err(1, "setresuid %u", pw->pw_uid);
	}
}

void
proc_exec(char *progname, int fds[DHTD_NUMPROC])
{
	size_t proc, i;
	char *argv[] = { progname, "-P", NULL /* title */, NULL };
	const size_t proc_i = 2;
	int sv[2];
	size_t nfd = 0;
	int fd;


	for (proc = 0; proc < nitems(procs); proc++) {
		argv[proc_i] = procs[proc].title;
		for (i = 0; i < DHTD_NUMPROC; i++) {
			if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, PF_UNSPEC, sv) == -1) {
				err(1, "socketpair");
			}

			switch (fork()) {
			case -1:
				err(1, "fork");
				break;
			case 0:
				if (setsid() == -1) {
					err(1, "setsid");
				}

				if (sv[0] != CONTROL_FILENO) {
					if ((sv[0] = dup2(sv[0], CONTROL_FILENO)) == -1) {
						err(1, "dup2");
					}
				} else if (fcntl(sv[0], F_SETFD, 0) == -1) {
					err(1, "fcntl");
				}

				if ((fd = open(_PATH_DEVNULL, O_RDWR, 0)) == -1) {
					err(1, "open %s", _PATH_DEVNULL);
				}
				if (dup2(fd, STDIN_FILENO) == -1
					|| dup2(fd, STDOUT_FILENO) == -1
					|| dup2(fd, STDERR_FILENO) == -1) {
					err(1, "dup2");
				}
				if (fd > STDERR_FILENO && close(fd) == -1) {
					err(1, "close");
				}

				execvp(argv[0], argv);
				err(1, "execvp %s", argv[0]);
				break;
			default:
				if (close(sv[0]) == -1) {
					err(1, "close");
				}
				fds[nfd++] = sv[1];
				break;
			}
		}
	}
}
