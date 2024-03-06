// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

// checking for redirections and perfoming them if they exist
void check_redirections(simple_command_t *s)
{
	int fd, rc;
	char *in_str = get_word(s->in);
	char *out_str = get_word(s->out);
	char *err_str = get_word(s->err);


	if (s->out != NULL && s->err != NULL && !strcmp(err_str, out_str)) {
		fd = open(out_str, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		DIE(fd == -1, "open");

		rc = dup2(fd, STDOUT_FILENO);
		DIE(rc == -1, "dup2");
		rc = dup2(fd, STDERR_FILENO);
		DIE(rc == -1, "dup2");

		close(fd);
		free(err_str);
		free(out_str);
	} else {
		if (s->out != NULL) {
			if (s->io_flags & IO_OUT_APPEND) {
				fd = open(out_str, O_WRONLY | O_CREAT | O_APPEND, 0644);
				DIE(fd == -1, "open");
			} else {
				fd = open(out_str, O_WRONLY | O_CREAT | O_TRUNC, 0644);
				DIE(fd == -1, "open");
			}

			rc = dup2(fd, STDOUT_FILENO);
			DIE(rc == -1, "dup2");

			close(fd);
			free(out_str);
		}

		if (s->err != NULL) {
			if (s->io_flags & IO_ERR_APPEND) {
				fd = open(err_str, O_WRONLY | O_CREAT | O_APPEND, 0644);
				DIE(fd == -1, "open");
			} else {
				fd = open(err_str, O_WRONLY | O_CREAT | O_TRUNC, 0644);
				DIE(fd == -1, "open");
			}

			rc = dup2(fd, STDERR_FILENO);
			DIE(rc == -1, "dup2");

			close(fd);
			free(err_str);
		}
	}

	if (s->in != NULL) {
		fd = open(in_str, O_RDONLY);
		DIE(fd == -1, "open");

		rc = dup2(fd, STDIN_FILENO);
		DIE(rc == -1, "dup2");

		close(fd);
		free(in_str);
	}
}

// perform dup for standard fds to make copies for restore function
void duplicate_fd(int *in, int *out, int *err)
{
	*in = dup(STDIN_FILENO);
	DIE(*in == -1, "dup");
	*out = dup(STDOUT_FILENO);
	DIE(*out == -1, "dup");
	*err = dup(STDERR_FILENO);
	DIE(*err == -1, "dup");
}

// restore standard fds after redirection
void restore_fd(int in, int out, int err)
{
	int rc;

	rc = dup2(in, STDIN_FILENO);
	DIE(rc == -1, "dup2");
	rc = dup2(out, STDOUT_FILENO);
	DIE(rc == -1, "dup2");
	rc = dup2(err, STDERR_FILENO);
	DIE(rc == -1, "dup2");

	close(in);
	close(out);
	close(err);
}

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* TODO: Execute cd. */
	int ret;

	ret = chdir(dir->string);

	if (!ret)
		return 0;

	return 1;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */
	return SHELL_EXIT; /* TODO: Replace with actual exit code. */
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */
	if (s == NULL)
		return SHELL_EXIT;

	int ret;

	/* TODO: If builtin command, execute the command. */
	char *cmd = get_word(s->verb);

	if (!strcmp(cmd, "pwd")) {
		int in, out, err;
		char *buf = NULL;

		duplicate_fd(&in, &out, &err);
		check_redirections(s);
		buf = getcwd(NULL, 0);

		if (buf != NULL) {
			printf("%s\n", buf);
			fflush(stdout);
			free(buf);
			ret = EXIT_SUCCESS;
		} else {
			fprintf(stderr, "Execution failed for pwd\n");
			ret = EXIT_FAILURE;
		}

		restore_fd(in, out, err);
		free(cmd);
	} else if (!strcmp(cmd, "cd")) {
		if (s->params != NULL) {
			int in, out, err;

			duplicate_fd(&in, &out, &err);
			check_redirections(s);
			ret = shell_cd(s->params);

			if (ret)
				fprintf(stderr, "no such file or directory\n");

			restore_fd(in, out, err);
		}

		free(cmd);
	} else if (!strcmp(cmd, "exit") || !(strcmp(cmd, "quit"))) {
		ret = shell_exit();
		free(cmd);

	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	} else if (s->verb->next_part != NULL && !strcmp(s->verb->next_part->string, "=")) {
		char *value = get_word(s->verb->next_part->next_part);

		ret = setenv(s->verb->string, value, 1);

		if (!ret)
			ret = EXIT_SUCCESS;
		else
			ret = EXIT_FAILURE;

		free(value);
		free(cmd);

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */
	} else {
		pid_t pid, ret_pid;
		int size, status;

		pid = fork();

		switch (pid) {
		case -1:
			DIE(pid == -1, "fork");
			break;

		case 0:
			check_redirections(s);
			ret = execvp(cmd, get_argv(s, &size));

			if (ret == -1) {
				fprintf(stderr, "Execution failed for '%s'\n", cmd);
				exit(EXIT_FAILURE);
			}

		default:
			ret_pid = waitpid(pid, &status, 0);
			DIE(ret_pid == -1, "waitpid");

			if (WIFEXITED(status))
				ret = WEXITSTATUS(status);
			else
				ret = EXIT_FAILURE;

			free(cmd);
		}
	}

	return ret; /* TODO: Replace with actual exit status. */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */
	pid_t pid_cmd1, pid_cmd2, ret_pid_cmd1, ret_pid_cmd2;
	int ret, status_cmd1, status_cmd2;

	pid_cmd1 = fork();

	switch (pid_cmd1) {
	case -1:
		DIE(pid_cmd1 == -1, "fork");
		break;

	case 0:
		ret = parse_command(cmd1, level, father);
		exit(ret);

	default:
		pid_cmd2 = fork();

		switch (pid_cmd2) {
		case -1:
			DIE(pid_cmd2 == -1, "fork");
			break;

		case 0:
			ret = parse_command(cmd2, level, father);
			exit(ret);

		default:
			ret_pid_cmd1 = waitpid(pid_cmd1, &status_cmd1, 0);
			DIE(ret_pid_cmd1 == -1, "waitpid");
			ret_pid_cmd2 = waitpid(pid_cmd2, &status_cmd2, 0);
			DIE(ret_pid_cmd2 == -1, "waitpid");

			if (WIFEXITED(status_cmd1) && WIFEXITED(status_cmd2))
				ret = WEXITSTATUS(status_cmd1) | WEXITSTATUS(status_cmd2);
			else
				ret = EXIT_FAILURE;

			break;
		}

		break;
	}

	return ret; /* TODO: Replace with actual exit status. */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */
	int pipefd[2], rc, ret, status_cmd1, status_cmd2;
	pid_t pid_cmd1, pid_cmd2, ret_pid_cmd1, ret_pid_cmd2;

	rc = pipe(pipefd);
	DIE(rc == -1, "pipe");

	pid_cmd1 = fork();

	switch (pid_cmd1) {
	case -1:
		close(pipefd[READ]);
		close(pipefd[WRITE]);
		DIE(pid_cmd1 == -1, "fork");
		break;

	case 0:
		close(pipefd[READ]);

		rc = dup2(pipefd[WRITE], STDOUT_FILENO);
		DIE(rc == -1, "dup2");

		close(pipefd[WRITE]);
		ret = parse_command(cmd1, level, father);
		exit(ret);

	default:
		pid_cmd2 = fork();

		switch (pid_cmd2) {
		case -1:
			close(pipefd[READ]);
			close(pipefd[WRITE]);
			DIE(pid_cmd2 == -1, "fork");
			break;

		case 0:
			close(pipefd[WRITE]);

			rc = dup2(pipefd[READ], STDIN_FILENO);
			DIE(rc == -1, "dup2");

			close(pipefd[READ]);
			ret = parse_command(cmd2, level, father);
			exit(ret);

		default:
			close(pipefd[READ]);
			close(pipefd[WRITE]);

			ret_pid_cmd1 = waitpid(pid_cmd1, &status_cmd1, 0);
			DIE(ret_pid_cmd1 == -1, "waitpid");
			ret_pid_cmd2 = waitpid(pid_cmd2, &status_cmd2, 0);
			DIE(ret_pid_cmd2 == -1, "waitpid");

			if (WIFEXITED(status_cmd1) && WIFEXITED(status_cmd2))
				ret = WEXITSTATUS(status_cmd2);
			else
				ret = EXIT_FAILURE;

			break;
		}

		break;
	}

	return ret; /* TODO: Replace with actual exit status. */
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO: sanity checks */
	if (c == NULL)
		return SHELL_EXIT;

	int ret;

	if (c->op == OP_NONE) {
		/* TODO: Execute a simple command. */
		return parse_simple(c->scmd, level, father);
		/* TODO: Replace with actual exit code of command. */
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO: Execute the commands one after the other. */
		ret = parse_command(c->cmd1, level, father);
		if (ret != SHELL_EXIT)
			ret = parse_command(c->cmd2, level, father);
		break;

	case OP_PARALLEL:
		/* TODO: Execute the commands simultaneously. */
		ret = run_in_parallel(c->cmd1, c->cmd2, level, father);
		break;

	case OP_CONDITIONAL_NZERO:
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */
		ret = parse_command(c->cmd1, level, father);
		if (ret && ret != SHELL_EXIT)
			ret = parse_command(c->cmd2, level, father);
		break;

	case OP_CONDITIONAL_ZERO:
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */
		ret = parse_command(c->cmd1, level, father);
		if (!ret)
			ret = parse_command(c->cmd2, level, father);
		break;

	case OP_PIPE:
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */
		ret = run_on_pipe(c->cmd1, c->cmd2, level, father);
		break;

	default:
		return SHELL_EXIT;
	}

	return ret; /* TODO: Replace with actual exit code of command. */
}
