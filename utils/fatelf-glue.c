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

static int fatelf_glue(const char *out, const char **bins, const int bincount)
{
    int i = 0;
    const size_t struct_size = fatelf_header_size(bincount);
    FATELF_header *header = (FATELF_header *) xmalloc(struct_size);
    const int outfd = xopen(out, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    uint64_t offset = FATELF_DISK_FORMAT_SIZE(bincount);

    unlink_on_xfail = out;

    if (bincount == 0)
        xfail("Nothing to do.");
    else if (bincount > 0xFF)
        xfail("Too many binaries (max is 255).");

    // pad out some bytes for the header we'll write at the end...
    xwrite_zeros(out, outfd, (size_t) offset);

    header->magic = FATELF_MAGIC;
    header->version = FATELF_FORMAT_VERSION;
    header->num_records = bincount;

    struct {
        int idx;
        uint64_t offset;
        uint64_t size;
    } haiku = {
        .idx = -1
    };

    for (i = 0; i < bincount; i++)
    {
        int j = 0;
        const uint64_t binary_offset = align_to_page(offset);
        const char *fname = bins[i];
        const int fd = xopen(fname, O_RDONLY, 0755);
        FATELF_record *record = &header->records[i];

        xread_elf_header(fname, fd, 0, record);
        record->offset = binary_offset;

        // make sure we don't have a duplicate target.
        for (j = 0; j < i; j++)
        {
            if (fatelf_record_matches(record, &header->records[j]))
                xfail("'%s' and '%s' are for the same target.", bins[j], fname);
        } // for

        // append this binary to the final file, padded to page alignment.
        xwrite_zeros(out, outfd, (size_t) (binary_offset - offset));

        // detect and skip Haiku resource data
        if (haiku_find_elf_rsrc(fname, fd, &haiku.offset, &haiku.size)) {
            if (haiku.idx == -1)
                haiku.idx = i;

            record->size = xget_file_size(fname, fd) - haiku.size;
            xcopyfile_range(fname, fd, out, outfd, 0, record->size);
        } else {
            record->size = xcopyfile(fname, fd, out, outfd);
        }

        offset = binary_offset + record->size;

        // done with this binary!
        xclose(fname, fd);
    } // for

    // rather then perform any complex merging of resources, we select the
    // resources from the first file.
    if (haiku.idx >= 0) {
        const char *fname = bins[haiku.idx];
        const int fd = xopen(fname, O_RDONLY, 0755);

        if (haiku_fat_rsrc_offset(out, outfd, header, &offset)) {
            xlseek(out, outfd, offset, SEEK_SET);
            xcopyfile_range(fname, fd, out, outfd, haiku.offset, haiku.size);
        }

        xclose(fname, fd);
    }

    // Write the actual FatELF header now...
    xwrite_fatelf_header(out, outfd, header);
    xclose(out, outfd);
    free(header);

    unlink_on_xfail = NULL;

    return 0;  // success.
} // fatelf_glue


int main(int argc, const char **argv)
{
    xfatelf_init(argc, argv);
    if (argc < 4)  // this could stand to use getopt(), later.
        xfail("USAGE: %s <out> <bin1> <bin2> [... binN]", argv[0]);
    return fatelf_glue(argv[1], &argv[2], argc - 2);
} // main

// end of fatelf-glue.c ...

