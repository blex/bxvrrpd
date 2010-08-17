#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "daemon.h"

int daemonize(int nochdir, int noclose)
{
	int fd;

	switch (fork()) {
	case -1:
		return -1;
	case 0:
		break;
	default:
		exit(0);
	}

	if (setsid() == -1) return -1;
	if (!nochdir) chdir("/");
	if (noclose) return 0;

	fd = open(_PATH_DEVNULL, O_RDWR, 0);
	if (fd != -1) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > 2) close(fd);
	}
	return 0;
}
