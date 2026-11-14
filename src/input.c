#define _POSIX_C_SOURCE 200809L

#include "input.h"

#include "monocypher.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static volatile sig_atomic_t caught_signal;

#if !defined(_WIN32)
static struct termios saved_termios;
static int echo_disabled;

static void restore_terminal(void)
{
    if (echo_disabled) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_termios);
        echo_disabled = 0;
    }
}

static void record_signal(int signal_number)
{
    caught_signal = signal_number;
}

static void set_terminal_signal_handler(void (*handler)(int))
{
    static const int terminal_signals[] = {
        SIGINT, SIGTERM, SIGHUP, SIGQUIT
    };
    struct sigaction action;
    size_t i;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    for (i = 0; i < sizeof(terminal_signals) / sizeof(terminal_signals[0]);
         i++)
        (void)sigaction(terminal_signals[i], &action, NULL);
}

static void install_terminal_handlers(void)
{
    caught_signal = 0;
    set_terminal_signal_handler(record_signal);
}

static void restore_signal_handlers(void)
{
    set_terminal_signal_handler(SIG_DFL);
}

static void disable_echo(void)
{
    struct termios hidden;

    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &saved_termios) != 0)
        return;

    hidden = saved_termios;
    hidden.c_lflag &= (tcflag_t)~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0)
        echo_disabled = 1;
}
#endif

static int is_blank(unsigned char c)
{
    return c == ' ' || c == '\t';
}

static int printable_ascii(unsigned char c)
{
    return c >= 0x20 && c <= 0x7e;
}

static void lowercase_ascii(char *s, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (s[i] >= 'A' && s[i] <= 'Z')
            s[i] = (char)(s[i] - 'A' + 'a');
    }
}

static void trim_blanks(const unsigned char *data, size_t len,
                        size_t *start, size_t *end)
{
    size_t s = 0;
    size_t e = len;

    while (s < e && is_blank(data[s]))
        s++;
    while (e > s && is_blank(data[e - 1]))
        e--;

    *start = s;
    *end = e;
}

int normalize_email(const char *input, char **output)
{
    size_t len = strlen(input);
    size_t start;
    size_t end;
    size_t at_count = 0;
    size_t at_pos = 0;
    size_t i;
    char *result;

    trim_blanks((const unsigned char *)input, len, &start, &end);

    if (start == end)
        return -1;

    for (i = start; i < end; i++) {
        unsigned char c = (unsigned char)input[i];

        if (!printable_ascii(c))
            return -1;
        if (c == '@') {
            at_count++;
            at_pos = i - start;
        }
    }

    if (at_count != 1 || at_pos == 0 || at_pos + 1 == end - start)
        return -1;

    result = (char *)malloc(end - start + 1);
    if (result == NULL)
        return -1;
    memcpy(result, input + start, end - start);
    result[end - start] = '\0';
    lowercase_ascii(result, end - start);
    *output = result;
    return 0;
}

int normalize_passphrase(const unsigned char *input, size_t input_len,
                         char **output)
{
    size_t start;
    size_t end;
    size_t i;
    size_t out_len = 0;
    size_t words = 0;
    int in_word = 0;
    char *result;

    trim_blanks(input, input_len, &start, &end);

    if (start == end)
        return -1;

    for (i = start; i < end; i++) {
        if (!is_blank(input[i]) && !printable_ascii(input[i]))
            return -1;
    }

    result = (char *)malloc(end - start + 1);
    if (result == NULL)
        return -1;

    for (i = start; i < end; i++) {
        unsigned char c = input[i];

        if (is_blank(c)) {
            if (in_word) {
                result[out_len++] = ' ';
                in_word = 0;
            }
        } else {
            if (!in_word) {
                words++;
                in_word = 1;
            }
            result[out_len++] = (char)c;
        }
    }
    if (out_len != 0 && result[out_len - 1] == ' ')
        out_len--;
    result[out_len] = '\0';
    lowercase_ascii(result, out_len);

    if (words < 4) {
        crypto_wipe(result, end - start + 1);
        free(result);
        return -1;
    }

    *output = result;
    return 0;
}

int read_passphrase(unsigned char **output, size_t *output_len)
{
    unsigned char *line = NULL;
    size_t len = 0;
    size_t cap = 0;
    int result = -1;
    int eof = 0;
    int interactive = isatty(STDIN_FILENO);

    if (interactive &&
        (fputs("Passphrase: ", stderr) == EOF || fflush(stderr) != 0))
        return -1;

#if !defined(_WIN32)
    if (interactive) {
        install_terminal_handlers();
        disable_echo();
    }
#else
    (void)interactive;
#endif

    for (;;) {
        unsigned char byte;
        ssize_t count = read(STDIN_FILENO, &byte, 1);

        if (count == 1) {
            if (byte == '\n')
                break;

            if (len == cap) {
                size_t new_cap = cap == 0 ? 128 : cap * 2;
                unsigned char *new_line;

                if (new_cap < cap || new_cap > UINT32_MAX) {
                    result = -2;
                    goto finish;
                }
                new_line = (unsigned char *)malloc(new_cap + 1);
                if (new_line == NULL) {
                    result = -2;
                    goto finish;
                }
                if (line != NULL) {
                    memcpy(new_line, line, len);
                    crypto_wipe(line, cap + 1);
                    free(line);
                }
                line = new_line;
                cap = new_cap;
            }
            line[len++] = byte;
            continue;
        }

        if (count == 0) {
            eof = 1;
            break;
        }

        if (errno == EINTR) {
            if (caught_signal) {
                result = -4;
                goto finish;
            }
            continue;
        }

        result = -2;
        goto finish;
    }

    if (len == 0 && eof) {
        result = -3;
        goto finish;
    }

    if (line == NULL) {
        line = (unsigned char *)malloc(1);
        if (line == NULL) {
            result = -2;
            goto finish;
        }
    }
    line[len] = '\0';

    *output = line;
    *output_len = len;
    line = NULL;
    result = 0;

finish:
#if !defined(_WIN32)
    if (interactive) {
        restore_terminal();
        (void)fputc('\n', stderr);
        (void)fflush(stderr);
    }
#endif
    if (line != NULL) {
        crypto_wipe(line, cap + 1);
        free(line);
    }
#if !defined(_WIN32)
    if (interactive) {
        sigset_t blocked;
        int pending_signal;

        sigemptyset(&blocked);
        sigaddset(&blocked, SIGINT);
        sigaddset(&blocked, SIGTERM);
        sigaddset(&blocked, SIGHUP);
        sigaddset(&blocked, SIGQUIT);
        (void)sigprocmask(SIG_BLOCK, &blocked, NULL);
        pending_signal = (int)caught_signal;
        restore_signal_handlers();
        (void)sigprocmask(SIG_UNBLOCK, &blocked, NULL);

        if (pending_signal != 0) {
            (void)raise(pending_signal);
            result = -4;
        }
    }
#endif
    return result;
}
