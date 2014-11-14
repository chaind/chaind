#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libchain/libchain.h>
#include <Judy.h>

#include "chaind.h"
#include "config.h"
#include "logging.h"

assert_compile_time(sizeof(size_t) == 8);
assert_compile_time(sizeof(Word_t) == sizeof(uintptr_t));

// Not a fan of this being a global state, but it's necessary to 
// exit due to signal handling
static struct chaind* global_chaind = NULL;

static void help(char const* name)
{
    fprintf(stderr, "Usage: %s -c chaind.conf [-f] [-h]\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t-c chaind.conf\t\tspecify the configuration file (required)\n");
    fprintf(stderr, "\t-f            \t\tdon't fork (run in foreground)\n");
    fprintf(stderr, "\t-h            \t\tshow this help\n");
    fprintf(stderr, "\n");
    exit(-1);
}

static void handle_signal(int signum, siginfo_t* info, void* context)
{
    switch(signum) {
    case SIGUSR1:
    case SIGINT:
    case SIGTERM:
        if(global_chaind != NULL) {
            chaind_request_exit(global_chaind);
        }
        break;
    default:
        break;
    }
}

int main(int argc, char* argv[])
{
    int c;
    char const* config_file = NULL;
    int foreground = 0;

    while((c = getopt(argc, argv, "c:fh")) != -1) {
        switch(c) {
        case 'c':
            config_file = optarg;
            break;
        case 'f':
            foreground = 1;
            break;
        case 'h':
        default:
            help(argv[0]);
            break;
        }
    }

    if(config_file == NULL || optind < argc) {
        help(argv[0]);
        return 0;
    }

    struct config* cfg = config_load(config_file);
    if(cfg == NULL) return 0;

    pid_t fork_result = 0;
    
    if(!foreground) {
        fork_result = fork();
    }

    int result = 0;

    if(fork_result == 0) {
        struct sigaction sa;

        sa.sa_sigaction = &handle_signal;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigfillset(&sa.sa_mask);

        if(sigaction(SIGINT, &sa, NULL) < 0 
          || sigaction(SIGUSR1, &sa, NULL) < 0
          || sigaction(SIGTERM, &sa, NULL) < 0) {
            perror(argv[0]);
            return -1;
        }

        int log_flags = LOG_NOWAIT;
        if(foreground) log_flags |= LOG_CONS;

        int facility = foreground ? LOG_LOCAL1 : LOG_DAEMON;
        openlog("chaind", log_flags, facility);
        setlogmask(LOG_UPTO(cfg->logging.level));
        log_notice("chaind started (pid = %d)", getpid());

        if((global_chaind = chaind_init(cfg)) == NULL) {
            result = -1;
            goto done;
        }

        while(chaind_update(global_chaind) == 0) {
            if(usleep(1000) < 0 && errno != EINTR) {
                perror("usleep");
                result = -1;
                goto done;
            }
        }

        result = chaind_deinit(global_chaind);
        log_notice("chaind exiting...");
        closelog();
    }

done:
    config_free(cfg);
    return result;
}
