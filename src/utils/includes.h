/*
 * wpa_supplicant/hostapd - Default include files
 * Copyright (c) 2005-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This header file is included into all C files so that commonly used header
 * files can be selected with OS specific ifdef blocks in one place instead of
 * having to have OS/C library specific selection in many files.
 */

#ifndef INCLUDES_H
#define INCLUDES_H

/* Include possible build time configuration before including anything else */
#include "build_config.h"

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#ifndef _WIN32_WCE
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#endif /* _WIN32_WCE */
#include <ctype.h>

#if !(defined(MSC_VER) || defined(CONFIG_ZEPHYR))
#include <unistd.h>
#endif /* _MSC_VER */

#if !(defined(CONFIG_NATIVE_WINDOWS) || defined(CONFIG_ZEPHYR))
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifndef __vxworks
#include <sys/uio.h>
#include <sys/time.h>
#endif /* __vxworks */
#endif /* CONFIG_NATIVE_WINDOWS */

#if defined(CONFIG_ZEPHYR)
#include <strings.h>
#if defined(CONFIG_POSIX_API)
#include <zephyr/posix/arpa/inet.h>
#include <zephyr/posix/sys/select.h>
#include <zephyr/posix/sys/socket.h>
#include <zephyr/posix/unistd.h>
#else /* defined(CONFIG_POSIX_API) */
#include <sys/select.h>
#include <zephyr/net/net_ip.h>
#endif /* defined(CONFIG_POSIX_API) */
#include <zephyr/shell/shell.h>
#endif /* defined(CONFIG_ZEPHYR) */

#endif /* INCLUDES_H */
