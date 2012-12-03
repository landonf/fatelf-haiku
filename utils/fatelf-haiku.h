/*
 * Copyright 2012, Haiku Inc. All Rights Reserved.
 * Copyright 2002-2009, Ingo Weinhold, ingo_weinhold@gmx.de.
 * Distributed under the terms of the MIT License.
 * 
 * Authors:
 *		Landon Fuller <landonf@bikemonkey.org>
 *		Ingo Weinhold <ingo_weinhold@gmx.de>
 */

#ifndef FATELF_HAIKU_H
#define FATELF_HAIKU_H

int haiku_fat_rsrc_offset(const char *fname, const int fd,
                                  const FATELF_header *header,
                                  uint64_t *offset);
int haiku_elf_rsrc_offset(const char *fname, const int fd, uint64_t *offset);


int haiku_find_elf_rsrc(const char *fname, const int fd, uint64_t *offset,
                        uint64_t *size);
int haiku_find_fatelf_rsrc(const char *fname, const int fd,
                     const FATELF_header *header, uint64_t *offset,
                     uint64_t *size);

#endif /* FATELF_HAIKU_H */
