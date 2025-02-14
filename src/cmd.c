// SPDX-License-Identifier: BSD-3-Clause

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define READ 0
#define WRITE 1

#define IO_REGULAR 0x00
#define IO_OUT_APPEND 0x01
#define IO_ERR_APPEND 0x02

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* TODO: Execute cd. */
	if (dir == NULL || dir->next_word != NULL)
		return false;

	char *path = get_word(dir);

	if (path == NULL)
		return false;

	if (chdir(path) != 0) {
		free(path);
		return false;
	}

	free(path);
	return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */
	return SHELL_EXIT;
}

static void handle_redirection(simple_command_t *cmd)
{
	if (cmd->in) {
		int fd_in = open(get_word(cmd->in), O_RDONLY);

		if (fd_in == -1)
			return;

		if (dup2(fd_in, STDIN_FILENO) == -1) {
			close(fd_in);
			return;
		}

		close(fd_in);
	}

	// string literals can be found in both the out list and the err list
	if (cmd->out && cmd->err && strcmp(cmd->out->string, cmd->err->string) == 0) {
		int fd;

		if (cmd->io_flags) {
			fd = open(get_word(cmd->out), O_WRONLY | O_CREAT | O_APPEND, 0644);
			if (fd == -1)
				return;
		} else {
			fd = open(get_word(cmd->out), O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (fd == -1)
				return;
		}

		if (dup2(fd, STDOUT_FILENO) == -1) {
			close(fd);
			return;
		}

		if (dup2(fd, STDERR_FILENO) == -1) {
			close(fd);
			return;
		}

		close(fd);
	} else {
		if (cmd->out) {
			int fd_out;

			if (cmd->io_flags) {
				fd_out = open(get_word(cmd->out), O_WRONLY | O_CREAT | O_APPEND, 0644);
				if (fd_out == -1)
					return;
			} else {
				fd_out = open(get_word(cmd->out), O_WRONLY | O_CREAT | O_TRUNC, 0644);
				if (fd_out == -1)
					return;
			}

			if (dup2(fd_out, STDOUT_FILENO) == -1) {
				close(fd_out);
				return;
			}

			close(fd_out);
		}

		if (cmd->err) {
			int fd_err;

			if (cmd->io_flags) {
				fd_err = open(get_word(cmd->err), O_WRONLY | O_CREAT | O_APPEND, 0644);
				if (fd_err == -1)
					return;
			} else {
				fd_err = open(get_word(cmd->err), O_WRONLY | O_CREAT | O_TRUNC, 0644);
				if (fd_err == -1)
					return;
			}

			if (dup2(fd_err, STDERR_FILENO) == -1) {
				close(fd_err);
				return;
			}

			close(fd_err);
		}
	}
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */
	if (!s || !s->verb)
		return -1;

	/* TODO: If builtin command, execute the command. */
	char *command_name = get_word(s->verb);

	if (strcmp(command_name, "cd") == 0) {
		free(command_name);
		int out_copy = -1;
		int err_copy = -1;

		if (s->out) {
			int fd = open(s->out->string, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			if (fd < 0)
				return -1;

			out_copy = dup(STDOUT_FILENO);
			dup2(fd, STDOUT_FILENO);
			close(fd);
		}

		if (s->err) {
			int fd = open(s->err->string, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			if (fd < 0) {
				if (out_copy != -1) {
					dup2(out_copy, STDOUT_FILENO);
					close(out_copy);
				}

				return -1;
			}

			err_copy = dup(STDERR_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);
		}

		int result = shell_cd(s->params) ? 0 : 1;

		if (out_copy != -1) {
			dup2(out_copy, STDOUT_FILENO);
			close(out_copy);
		}

		if (err_copy != -1) {
			dup2(err_copy, STDERR_FILENO);
			close(err_copy);
		}

		return result;
	}

	if (strcmp(command_name, "exit") == 0 || strcmp(command_name, "quit") == 0) {
		free(command_name);
		return shell_exit();
	}

	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	// ex: NAME="John Doe"
	if (strchr(command_name, '=') != NULL) {
		char *equal_sign = strchr(command_name, '=');

		if (equal_sign != NULL) {
			size_t name_len = equal_sign - command_name;
			char *name = strndup(command_name, name_len);
			char *value = strdup(equal_sign + 1);

			if (setenv(name, value, 1) == -1) {
				free(name);
				free(value);
				return -1;
			}

			free(name);
			free(value);
			return 0;
		}
	}

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */
	pid_t pid = fork();

	if (pid < 0) {
		free(command_name);
		return -1;
	}

	if (pid == 0) {
		int argc;
		char **argv = get_argv(s, &argc);

		if (argv == NULL)
			return -1;

		handle_redirection(s);

		int exit_status = execvp(argv[0], argv);

		if (exit_status)
			printf("Execution failed for '%s'\n", command_name);

		exit(exit_status);
		free(argv);
		free(command_name);
		return -1;
	}

	int status;

	waitpid(pid, &status, 0);
	free(command_name);

	return WEXITSTATUS(status);
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */
	pid_t pid1 = fork();

	if (pid1 == 0) {
		parse_command(cmd1, level + 1, father);
		exit(EXIT_SUCCESS);
	}

	pid_t pid2 = fork();

	if (pid2 == 0) {
		parse_command(cmd2, level + 1, father);
		exit(EXIT_SUCCESS);
	}

	int status1, status2;

	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	return WEXITSTATUS(status2);
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	int pipefd[2];

	if (pipe(pipefd) == -1)
		return false;


	pid_t pid1 = fork();

	if (pid1 < 0)
		return false;

	if (pid1 == 0) {
		close(pipefd[READ]);
		dup2(pipefd[WRITE], STDOUT_FILENO);
		close(pipefd[WRITE]);

		int ret = parse_command(cmd1, level + 1, father);

		exit(ret);
	}

	pid_t pid2 = fork();

	if (pid2 < 0)
		return false;

	if (pid2 == 0) {
		close(pipefd[WRITE]);
		dup2(pipefd[READ], STDIN_FILENO);
		close(pipefd[READ]);

		int ret = parse_command(cmd2, level + 1, father);

		exit(ret);
	}

	close(pipefd[READ]);
	close(pipefd[WRITE]);

	int status1, status2;

	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	return WEXITSTATUS(status2);
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	if (!c)
		return shell_exit();

	if (c->op == OP_NONE)
		return parse_simple(c->scmd, level, father);

	int ret = 1;

	switch (c->op) {
	case OP_PIPE:
		ret = run_on_pipe(c->cmd1, c->cmd2, level, father);
		break;

	case OP_CONDITIONAL_NZERO:
		ret = parse_command(c->cmd1, level, father);
		if (ret != 0)
			ret = parse_command(c->cmd2, level, father);

		break;

	case OP_CONDITIONAL_ZERO:
		ret = parse_command(c->cmd1, level, father);
		if (ret == 0)
			ret = parse_command(c->cmd2, level, father);

		break;

	case OP_SEQUENTIAL:
		parse_command(c->cmd1, level, father);
		ret = parse_command(c->cmd2, level, father);
		break;

	case OP_PARALLEL:
		ret = run_in_parallel(c->cmd1, c->cmd2, level, father);
		break;

	default:
		return SHELL_EXIT;
	}

	return ret;
}
