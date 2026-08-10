# SPDX-FileCopyrightText: 2026 cfm-miku-en
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.18.1)

project(arpnative C)

add_library(arpnative SHARED arpnative.c)

# Hide everything that is not explicitly ARP_EXPORT. Two visible symbols instead
# of a full table makes the library meaningfully less pleasant to reverse, which
# is most of why the checks live down here rather than in C#.
target_compile_options(arpnative PRIVATE
    -fvisibility=hidden
    -fno-stack-protector
    -Os
    -Wall
    -Wextra
)

# Strip the rest at link time.
#
# max-page-size is 16 KB rather than the historical 4 KB: Android 15 moved to 16 KB
# pages and a library aligned for 4 KB will not load there. NDK r27+ already does
# this, but setting it explicitly means an older NDK produces a working .so too.
target_link_options(arpnative PRIVATE
    -Wl,--exclude-libs,ALL
    -Wl,--gc-sections
    -Wl,-z,max-page-size=16384
    -s
)

# No NDK libraries needed — raw syscalls only, and log output would be a gift to
# anyone watching logcat to find out what triggered.
