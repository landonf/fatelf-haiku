/*
 * Copyright 2012, Landon Fuller <landonf@bikemonkey.org>.
 * All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */

#ifndef FATELF_HAIKU_H
#define FATELF_HAIKU_H

int haiku_rsrc_offset(const char *fname, const int fd,
                      uint64_t *offset);

int haiku_find_rsrc(const char *fname, const int fd, uint64_t *offset,
                    uint64_t *size);

#endif /* FATELF_HAIKU_H */
