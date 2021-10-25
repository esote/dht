#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_IMSG
#include <imsg.h>
#else
#include "compat/imsg.h"
#endif

#include <event2/event.h>

#include "dhtd.h"

struct proc procs[PROC_MAX] = {
	[PROC_PARENT] = { "parent", PROC_PARENT, PARENT_ROOT, parent_start },
	[PROC_LISTEN] = { "listen", PROC_LISTEN, LISTEN_ROOT, listen_start },
	[PROC_RTABLE] = { "rtable", PROC_RTABLE, RTABLE_ROOT, rtable_start }
};

void sighandler(evutil_socket_t sig, short events, void *arg);
void usage(void);
struct proc *proc_search(const char *s);
void proc_init(const struct proc *proc);
void proc_exec(struct proc *proc, char *progname);
void proc_exec_single(struct proc *proc, size_t p, size_t i, char *argv[]);
void proc_run(struct proc *proc);
void parent_shutdown(struct proc *proc);

void
sighandler(evutil_socket_t sig, short events, void *arg)
{
	struct proc *proc = arg;
	(void)events;

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		parent_shutdown(proc);
		break;
	case SIGPIPE:
		/* ignore */
		break;
	case SIGCHLD:
	default:
		errx(1, "unexpected signal");
	}
}

void
usage(void)
{
	/* TODO */
	exit(1);
}

int
main(int argc, char *argv[])
{
	int c;
	struct proc *proc = &procs[PROC_PARENT];

	while ((c = getopt(argc, argv, "P:")) != -1) {
		switch (c) {
		case 'P':
			if ((proc = proc_search(optarg)) == NULL) {
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

	if (proc->id == PROC_PARENT) {
		proc_exec(proc, argv[0]);
	}

	proc_run(proc);
	return EXIT_SUCCESS;
}

struct proc *
proc_search(const char *s)
{
	size_t i;
	for (i = 0; i < nitems(procs); i++) {
		if (procs[i].id != PROC_PARENT && strcmp(s, procs[i].title) == 0) {
			return &procs[i];
		}
	}
	return NULL;
}

void
proc_init(const struct proc *proc)
{
	struct passwd *pw;

	if (setpgid(0, 0) == -1) {
		err(1, "setpgid");
	}

	if ((pw = getpwnam(DHTD_USER)) == NULL) {
		if (errno == 0) {
			errx(1, "getpwnam");
		} else {
			err(1, "getpwnam");
		}
	}

	if (chroot(proc->root) == -1) {
		err(1, "chroot %s", proc->root);
	}
	if (chdir("/") == -1) {
		err(1, "chdir '/'");
	}

	/* TODO: setproctitle proc->title */

	if (setgroups(1, &pw->pw_gid) == -1) {
		err(1, "setgroups %u", pw->pw_gid);
	}
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
		err(1, "setresgid %u", pw->pw_gid);
	}
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
		err(1, "setresuid %u", pw->pw_uid);
	}

	/* TODO: set up signal event handlers */
}

void
proc_exec(struct proc *proc, char *progname)
{
	size_t p, i;
	char *argv[] = { progname, "-P", NULL /* title */, NULL };
	const size_t proc_i = 2;

	for (p = 0; p < nitems(procs); p++) {
		if (procs[p].id == PROC_PARENT) {
			continue;
		}
		argv[proc_i] = procs[p].title;
		for (i = 0; i < DHTD_NUMPROC; i++) {
			proc_exec_single(proc, p, i, argv);
		}
	}
}

void
proc_exec_single(struct proc *proc, size_t p, size_t i, char *argv[])
{
	int sv[2];
	int fd;

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
		proc->pipes[p][i].fd = sv[1];
		break;
	}
}

void
proc_run(struct proc *proc)
{
	size_t p, i;
	struct pipe *pipe;

	if ((proc->evbase = event_base_new()) == NULL) {
		err(1, "event_base_new");
	}

	if ((proc->evsigint = evsignal_new(proc->evbase, SIGINT, sighandler, proc)) == NULL
		|| (proc->evsigterm = evsignal_new(proc->evbase, SIGTERM, sighandler, proc)) == NULL
		|| (proc->evsigchld = evsignal_new(proc->evbase, SIGCHLD, sighandler, proc)) == NULL
		|| (proc->evsigpipe = evsignal_new(proc->evbase, SIGPIPE, sighandler, proc)) == NULL) {
		err(1, "evsignal_new");
	}

	if (evsignal_add(proc->evsigint, NULL) == -1
		|| evsignal_add(proc->evsigterm, NULL) == -1
		|| evsignal_add(proc->evsigchld, NULL) == -1
		|| evsignal_add(proc->evsigpipe, NULL) == -1) {
		err(1, "evsignal_add");
	}

	if (proc->id == PROC_PARENT) {
		for (p = 0; p < nitems(procs); p++) {
			if (procs[p].id == PROC_PARENT) {
				continue;
			}
			for (i = 0; i < DHTD_NUMPROC; i++) {
				pipe = &proc->pipes[p][i];
				imsg_init(&pipe->ibuf, pipe->fd);
				/* TODO: event_new event_add */
			}
		}
	}
}

void
parent_shutdown(struct proc *proc)
{
	/* TODO */
	(void)proc;
	exit(1);
}
