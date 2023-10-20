/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <sys/time.h>

/* The clock_gettime() would be found in <zephyr/posix/time.h> but
 * that will cause conflict with picolib definition.
 */
int clock_gettime(clockid_t clock_id, struct timespec *ts);

#include <zephyr/random/random.h>

#include "includes.h"
#include "os.h"

void os_sleep(os_time_t sec, os_time_t usec)
{
	k_sleep(K_USEC(usec + USEC_PER_SEC * sec));
}

int os_get_time(struct os_time *t)
{
	int res;
	struct timeval tv;

	res = gettimeofday(&tv, NULL);
	t->sec = tv.tv_sec;
	t->usec = tv.tv_usec;
	return res;
}

int os_get_reltime(struct os_reltime *t)
{
#if defined(CLOCK_BOOTTIME)
	static clockid_t clock_id = CLOCK_BOOTTIME;
#elif defined(CLOCK_MONOTONIC)
	static clockid_t clock_id = CLOCK_MONOTONIC;
#else
	static clockid_t clock_id = CLOCK_REALTIME;
#endif
	struct timespec ts;
	int res;

	if (TEST_FAIL()) {
		return -1;
	}

	while (1) {
		res = clock_gettime(clock_id, &ts);
		if (res == 0) {
			t->sec = ts.tv_sec;
			t->usec = ts.tv_nsec / 1000;
			return 0;
		}
		switch (clock_id) {
#ifdef CLOCK_BOOTTIME
		case CLOCK_BOOTTIME:
			clock_id = CLOCK_MONOTONIC;
			break;
#endif
#ifdef CLOCK_MONOTONIC
		case CLOCK_MONOTONIC:
			clock_id = CLOCK_REALTIME;
			break;
#endif
		case CLOCK_REALTIME:
			return -1;
		}
	}
}

int os_mktime(int year, int month, int day, int hour, int min, int sec,
	      os_time_t *t)
{
	struct tm tm, *tm1;
	time_t t_local, t1, t2;
	os_time_t tz_offset;

	if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 ||
	    hour < 0 || hour > 23 || min < 0 || min > 59 || sec < 0 ||
	    sec > 60) {
		return -1;
	}

	memset(&tm, 0, sizeof(tm));
	tm.tm_year = year - 1900;
	tm.tm_mon = month - 1;
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min = min;
	tm.tm_sec = sec;

	t_local = mktime(&tm);

	/* figure out offset to UTC */
	tm1 = localtime(&t_local);
	if (tm1) {
		t1 = mktime(tm1);
		tm1 = gmtime(&t_local);
		if (tm1) {
			t2 = mktime(tm1);
			tz_offset = t2 - t1;
		} else {
			tz_offset = 0;
		}
	} else {
		tz_offset = 0;
	}

	*t = (os_time_t)t_local - tz_offset;
	return 0;
}

int os_gmtime(os_time_t t, struct os_tm *tm)
{
	struct tm *tm2;
	time_t t2 = t;

	tm2 = gmtime(&t2);
	if (tm2 == NULL) {
		return -1;
	}
	tm->sec = tm2->tm_sec;
	tm->min = tm2->tm_min;
	tm->hour = tm2->tm_hour;
	tm->day = tm2->tm_mday;
	tm->month = tm2->tm_mon + 1;
	tm->year = tm2->tm_year + 1900;
	return 0;
}

int os_daemonize(const char *pid_file)
{
	return -1;
}

void os_daemonize_terminate(const char *pid_file)
{
}

int os_get_random(unsigned char *buf, size_t len)
{
	sys_csrand_get(buf, len);

	return 0;
}

unsigned long os_random(void)
{
	return sys_rand32_get();
}

char *os_rel2abs_path(const char *rel_path)
{
	return NULL; /* strdup(rel_path) can be used here */
}

int os_program_init(void)
{
	return 0;
}

void os_program_deinit(void)
{
}

int os_setenv(const char *name, const char *value, int overwrite)
{
	return -1;
}

int os_unsetenv(const char *name)
{
	return -1;
}

char *os_readfile(const char *name, size_t *len)
{
	return NULL;
}

int os_fdatasync(FILE *stream)
{
	return 0;
}

char *os_strdup(const char *s)
{
	return strdup(s);
}

void *os_memdup(const void *src, size_t len)
{
	void *r = os_malloc(len);

	if (r && src) {
		os_memcpy(r, src, len);
	}
	return r;
}

void *os_zalloc(size_t size)
{
	return calloc(1, size);
}

int os_exec(const char *program, const char *arg, int wait_completion)
{
	return -1;
}

int os_memcmp_const(const void *a, const void *b, size_t len)
{
	return memcmp(a, b, len);
}
