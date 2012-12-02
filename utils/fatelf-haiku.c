/*
 * Copyright 2012, Landon Fuller <landonf@bikemonkey.org>.
 * All Rights Reserved.
 * Distributed under the terms of the MIT License.
 *
 * Adds support for merging and appending of Haiku/BeOS resource
 * data.
 */

#include <stdint.h>
#include <stdbool.h>

#define FATELF_UTILS 1
#include "fatelf-utils.h"

#include "fatelf-haiku.h"

#define HAIKU_ELF32_RSRC_ALIGN_MIN  32
#define HAIKU_ELF64_RSRC_ALIGN      8

#define ALIGN(v, a)     (((v + a - 1) / a) * a)

// Standard ELF definitions.
#define ELF_MAGIC   "\x7f""ELF"

#define EI_NIDENT   16
#define EI_CLASS    4
#define EI_DATA     5

#define PT_NULL     0

#define SHT_NULL        0
#define SHT_PROGBITS    1
#define SHT_NOBITS      8

typedef uint32_t    Elf32_Addr;
typedef uint16_t    Elf32_Half;
typedef uint32_t    Elf32_Off;
typedef int32_t     Elf32_Sword;
typedef uint32_t    Elf32_Word;

struct Elf32_Ehdr {
    uint8_t     e_ident[EI_NIDENT];
    Elf32_Half  e_type;
    Elf32_Half  e_machine;
    Elf32_Word  e_version;
    Elf32_Addr  e_entry;
    Elf32_Off   e_phoff;
    Elf32_Off   e_shoff;
    Elf32_Word  e_flags;
    Elf32_Half  e_ehsize;
    Elf32_Half  e_phentsize;
    Elf32_Half  e_phnum;
    Elf32_Half  e_shentsize;
    Elf32_Half  e_shnum;
    Elf32_Half  e_shstrndx;
};

struct Elf32_Shdr {
    Elf32_Word  sh_name;
    Elf32_Word  sh_type;
    Elf32_Word  sh_flags;
    Elf32_Addr  sh_addr;
    Elf32_Off   sh_offset;
    Elf32_Word  sh_size;
    Elf32_Word  sh_link;
    Elf32_Word  sh_info;
    Elf32_Word  sh_addralign;
    Elf32_Word  sh_entsize;
};

struct Elf32_Phdr {
    Elf32_Word  p_type;
    Elf32_Off   p_offset;
    Elf32_Addr  p_vaddr;
    Elf32_Addr  p_paddr;
    Elf32_Word  p_filesz;
    Elf32_Word  p_memsz;
    Elf32_Word  p_flags;
    Elf32_Word  p_align;
};

typedef uint64_t    Elf64_Addr;
typedef uint64_t    Elf64_Off;
typedef uint16_t    Elf64_Half;
typedef uint32_t    Elf64_Word;
typedef int32_t     Elf64_Sword;
typedef uint64_t    Elf64_Xword;
typedef int64_t    Elf64_Sxword;

struct Elf64_Ehdr {
    uint8_t     e_ident[EI_NIDENT];
    Elf64_Half  e_type;
    Elf64_Half  e_machine;
    Elf64_Word  e_version;
    Elf64_Addr  e_entry;
    Elf64_Off   e_phoff;
    Elf64_Off   e_shoff;
    Elf64_Word  e_flags;
    Elf64_Half  e_ehsize;
    Elf64_Half  e_phentsize;
    Elf64_Half  e_phnum;
    Elf64_Half  e_shentsize;
    Elf64_Half  e_shnum;
    Elf64_Half  e_shstrndx;
};

struct Elf64_Shdr {
    Elf64_Word  sh_name;
    Elf64_Word  sh_type;
    Elf64_Xword sh_flags;
    Elf64_Addr  sh_addr;
    Elf64_Off   sh_offset;
    Elf64_Xword sh_size;
    Elf64_Word  sh_link;
    Elf64_Word  sh_info;
    Elf64_Xword sh_addralign;
    Elf64_Xword sh_entsize;
};

struct Elf64_Phdr {
    Elf64_Word  p_type;
    Elf64_Word  p_flags;
    Elf64_Off   p_offset;
    Elf64_Addr  p_vaddr;
    Elf64_Addr  p_paddr;
    Elf64_Xword p_filesz;
    Elf64_Xword p_memsz;
    Elf64_Xword p_align;
};

struct elf_table_layout {
    uint64_t offset;
    uint64_t header_size;
    uint32_t header_count;
};

struct elf_layout {
    uint32_t header_size;
    struct elf_table_layout prog;
    struct elf_table_layout sect;
};

// Byteswap handlers
static uint16_t swap16 (uint16_t v) { return xswap16(v); }
static uint16_t nswap16 (uint16_t v) { return v; }

static uint32_t swap32 (uint32_t v) { return xswap32(v); }
static uint32_t nswap32 (uint32_t v) { return v; }

static uint64_t swap64 (uint64_t v) { return xswap64(v); }
static uint64_t nswap64 (uint64_t v) { return v; }


// Determine the file position of the Haiku resources within an ELF file. The
// returned offset may extend past the end of the file if no resources
// are available in the file.
bool xfind_haiku_rsrc_elf_offset (const char *fname, const int fd,
                                  uint64_t *offset)
{
    uint8_t ident[EI_NIDENT];

    xread(fname, fd, ident, sizeof(ident), 1);
    if (memcmp(ident, ELF_MAGIC, sizeof(ELF_MAGIC)) != 0)
        return false;

    uint64_t (*get64)(uint64_t v) = nswap64;
    uint32_t (*get32)(uint32_t v) = nswap32;
    uint16_t (*get16)(uint16_t v) = nswap16;

    if (ident[EI_DATA] != FATELF_HOST_ENDIAN) {
        get64 = swap64;
        get32 = swap32;
        get16 = swap16;
    }

    xlseek(fname, fd, 0, SEEK_SET);

    /* Parse the ELF header */
    struct elf_layout elfData;
    if (ident[EI_CLASS] == FATELF_32BITS) {
        struct Elf32_Ehdr ehdr;

        xread(fname, fd, &ehdr, sizeof(ehdr), 1);
        elfData.header_size = get16(ehdr.e_ehsize);

        elfData.prog.offset = get32(ehdr.e_phoff);
        elfData.prog.header_size = get16(ehdr.e_phentsize);
        elfData.prog.header_count = get16(ehdr.e_phnum);

        elfData.sect.offset = get32(ehdr.e_shoff);
        elfData.sect.header_size = get16(ehdr.e_shentsize);
        elfData.sect.header_count = get16(ehdr.e_shnum);

    } else if (ident[EI_CLASS] == FATELF_64BITS) {
        struct Elf64_Ehdr ehdr;

        xread(fname, fd, &ehdr, sizeof(ehdr), 1);
        elfData.header_size = get32(ehdr.e_ehsize);

        elfData.prog.offset = get64(ehdr.e_phoff);
        elfData.prog.header_size = get16(ehdr.e_phentsize);
        elfData.prog.header_count = get16(ehdr.e_phnum);

        elfData.sect.offset = get64(ehdr.e_shoff);
        elfData.sect.header_size = get16(ehdr.e_shentsize);
        elfData.sect.header_count = get16(ehdr.e_shnum);
    } else {
        xfail("'%s' has an invalid ELF EI_CLASS", fname);
    }

    /* Compute the offset to non-ELF data. For ELF files, this is based
     * on the offset to the end of the ELF data, plus either a fixed
     * alignment of 8 on ELF64, or on ELF32, the largest alignment value
     * specified in a Elf32_Phdr. */
    uint64_t rsrcOffset = 0;
    uint64_t rsrcAlign = 0;
    uint32_t i;

    if (elfData.prog.offset != 0) {
        uint64_t tableSize;
        uint64_t tableEnd;

        tableSize = elfData.prog.header_size * elfData.prog.header_count;
        tableEnd = elfData.prog.offset + tableSize;
        if (tableEnd > rsrcOffset)
            rsrcOffset = tableEnd;

        void *headers = xmalloc(tableSize);

        xread(fname, fd, headers, tableSize, 1);

        if (ident[EI_CLASS] == FATELF_32BITS) {
            struct Elf32_Phdr **phdrs = headers;
            for (i = 0; i < elfData.prog.header_count; i++) {
                struct Elf32_Phdr *phdr = phdrs[i];
                uint32_t type = get32(phdr->p_type);
                uint64_t offset = get32(phdr->p_offset);
                uint64_t size = get32(phdr->p_filesz);
                uint64_t alignment = get32(phdr->p_align);

                if (type == PT_NULL)
                    continue;

                uint64_t sectEnd = offset + size;
                if (sectEnd > rsrcOffset)
                    rsrcOffset = sectEnd;

                if (alignment > rsrcAlign)
                    rsrcAlign = alignment;
            }
        } else {
            struct Elf64_Phdr **phdrs = headers;
            for (i = 0; i < elfData.prog.header_count; i++) {
                struct Elf64_Phdr *phdr = phdrs[i];
                uint32_t type = get32(phdr->p_type);
                uint64_t offset = get64(phdr->p_offset);
                uint64_t size = get64(phdr->p_filesz);
                uint64_t alignment = get64(phdr->p_align);

                if (type == PT_NULL)
                    continue;

                uint64_t sectEnd = offset + size;
                if (sectEnd > rsrcOffset)
                    rsrcOffset = sectEnd;

                if (alignment > rsrcAlign)
                    rsrcAlign = alignment;
            }
        }
    }

    if (elfData.sect.offset != 0) {
        uint64_t tableSize;
        uint64_t tableEnd;

        tableSize = elfData.sect.header_size * elfData.sect.header_count;
        tableEnd = elfData.sect.offset + tableSize;
        if (tableEnd > rsrcOffset)
            rsrcOffset = tableEnd;

        void *headers = xmalloc(tableSize);
        xread(fname, fd, headers, tableSize, 1);
        if (ident[EI_CLASS] == FATELF_32BITS) {
            struct Elf32_Shdr **shdrs = headers;
            for (i = 0; i < elfData.sect.header_count; i++) {
                struct Elf32_Shdr *shdr = shdrs[i];
                uint32_t type = get32(shdr->sh_type);
                uint64_t offset = get32(shdr->sh_offset);
                uint64_t size = get32(shdr->sh_size);

                /* Skip sections that occupy no file space */
                if (type == SHT_NULL || type == SHT_NOBITS)
                    continue;

                uint64_t sectEnd = offset + size;
                if (sectEnd > rsrcOffset)
                    rsrcOffset = sectEnd;
            }
        } else {
            struct Elf64_Shdr **shdrs = headers;
            for (i = 0; i < elfData.sect.header_count; i++) {
                struct Elf64_Shdr *shdr = shdrs[i];
                uint32_t type = get32(shdr->sh_type);
                uint64_t offset = get64(shdr->sh_offset);
                uint64_t size = get64(shdr->sh_size);

                /* Skip sections that occupy no file space */
                if (type == SHT_NULL || type == SHT_NOBITS)
                    continue;

                uint64_t sectEnd = offset + size;
                if (sectEnd > rsrcOffset)
                    rsrcOffset = sectEnd;
            }
        }
    }

    // For 64-bit files, Haiku uses an 8 byte alignment for the resource header
    if (ident[EI_CLASS] == FATELF_64BITS)
        rsrcAlign = HAIKU_ELF64_RSRC_ALIGN;
    else if (rsrcAlign < HAIKU_ELF32_RSRC_ALIGN_MIN)
        rsrcAlign = HAIKU_ELF32_RSRC_ALIGN_MIN;

    *offset = ALIGN(rsrcOffset, rsrcAlign);

    return true;
}

// TODO
#if 0
int xfind_haiku_rsrc(const char *fname, const int fd,
                     const FATELF_header *header, uint64_t *offset,
                     uint64_t *size)
{
    const int furthest = find_furthest_record(header);
    if (furthest < 0)
        return 0;

    const uint64_t fsize = xget_file_size(fname, fd);
    const FATELF_record *rec = &header->records[furthest];
    const uint64_t edge = rec->offset + rec->size;
    if (fsize <= edge)
        return 0;

    // Extra data found
    *offset = edge;
    *size = fsize - edge;


    return 0;
}
#endif
