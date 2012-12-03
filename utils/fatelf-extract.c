/**
 * FatELF; support multiple ELF binaries in one file.
 *
 * Please see the file LICENSE.txt in the source's root directory.
 *
 *  This file written by Ryan C. Gordon.
 */

#define FATELF_UTILS 1
#include "fatelf-utils.h"
#include "fatelf-haiku.h"

static int fatelf_extract(const char *out, const char *fname, 
                          const char *target)
{
    const int fd = xopen(fname, O_RDONLY, 0755);
    FATELF_header *header = xread_fatelf_header(fname, fd);
    const int recidx = xfind_fatelf_record(header, target);
    const int outfd = xopen(out, O_RDWR | O_CREAT | O_TRUNC, 0755);
    const FATELF_record *rec = &header->records[recidx];

    unlink_on_xfail = out;

    xcopyfile_range(fname, fd, out, outfd, rec->offset, rec->size);

    struct {
        uint64_t offset;
        uint64_t size;
    } haiku;

    if (haiku_find_fatelf_rsrc(fname, fd, header, &haiku.offset, &haiku.size)) {
        uint64_t offset;
        if (!haiku_elf_rsrc_offset(out, outfd, &offset))
            xfail("Could not determine appropriate offset for Haiku resources");

        xlseek(out, outfd, offset, SEEK_SET);
        xcopyfile_range(fname, fd, out, outfd, haiku.offset, haiku.size);
    } else {
        xappend_junk(fname, fd, out, outfd);
    }

    xclose(out, outfd);
    xclose(fname, fd);
    free(header);

    unlink_on_xfail = NULL;

    return 0;  // success.
} // fatelf_extract


int main(int argc, const char **argv)
{
    xfatelf_init(argc, argv);
    if (argc != 4)  // this could stand to use getopt(), later.
        xfail("USAGE: %s <out> <in> <target>", argv[0]);
    return fatelf_extract(argv[1], argv[2], argv[3]);
} // main

// end of fatelf-extract.c ...

