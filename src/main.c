#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "vrrp_common.h"
#include "daemon.h"

extern struct vrrp_app app;
extern volatile int evt_shutdown;

//! @brief The signal handler of SIGINT and SIGTERM
//! @brief signo The signal number
static void handling_shutdown(int signo)
{
	evt_shutdown = 1;
}

int main(int argc, char **argv)
{	
	// Get arguments
	if (app.parse_args(argc, argv) < 0) exit(EXIT_FAILURE);

#ifdef DMSG 
	vrrp_dump(&app);
#endif
	openlog("bxvrrpd", LOG_PID, LOG_DAEMON);

	if (app.daemonize) {
		if (daemonize(0, 0) < 0) {
			VRRPLOG("Cannot daemonize\n");
			exit(EXIT_FAILURE);
		}
	}

	// Set signal handler
	struct sigaction shutdown_act;
	shutdown_act.sa_handler = handling_shutdown;
	sigemptyset(&shutdown_act.sa_mask);
	shutdown_act.sa_flags=0; 
	sigaction(SIGINT, &shutdown_act, NULL);
	sigaction(SIGKILL, &shutdown_act, NULL);
	sigaction(SIGTERM, &shutdown_act, NULL);

	//
	vrrp_initialize(&app);

	// Run it
	if (app.state_machine() < 0) { 
		VRRPLOG("State machine error\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
