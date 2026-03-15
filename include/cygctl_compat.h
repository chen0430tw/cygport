/*
 * cygctl_compat.h — Cygwin compatibility shims for ported Linux network tools
 *
 * Injected via -include into all compilation units by cygport.
 * Guards against common Windows/Cygwin header conflicts.
 */
#pragma once

/* Enable GNU extensions (strcasestr, etc.) before any system header */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

/* Ensure correct Windows API subset for Cygwin builds */
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif

/* NOTE: Do NOT define WIN32 here.
 * Cygwin defines __CYGWIN__ but NOT WIN32.
 * Tool-specific WIN32 guards are patched per-tool by cygport patches.
 * Defining WIN32 globally activates MSVC code paths (winfix.h, conio.h)
 * that don't exist under Cygwin. */

/* IPv6 socket options missing from some Windows/Cygwin w32api headers */
#ifndef IPV6_DSTOPTS
#  define IPV6_DSTOPTS 25
#endif
#ifndef IPV6_RTHDR
#  define IPV6_RTHDR   20
#endif
