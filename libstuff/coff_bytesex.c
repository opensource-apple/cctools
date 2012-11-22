#include <string.h>
#include "stuff/bytesex.h"
#include "coff/base_relocs.h"
#include "coff/ms_dos_stub.h"
#include "coff/filehdr.h"
#include "coff/aouthdr.h"
#include "coff/scnhdr.h"
#include "coff/syment.h"
#include "coff/bytesex.h"

__private_extern__
void
swap_base_relocation_block_header(
struct base_relocation_block_header *h,
enum byte_sex target_byte_sex)
{
	h->page_rva = SWAP_INT(h->page_rva);
	h->block_size = SWAP_INT(h->block_size);
}

__private_extern__
void
swap_base_relocation_entry(
struct base_relocation_entry *b,
unsigned long n,
enum byte_sex target_byte_sex)
{
    unsigned long i;
    enum byte_sex host_byte_sex;
    enum bool to_host_byte_sex;

    struct swapped_base_relocation_entry {
	union {
	    struct {
#if __BIG_ENDIAN__
		uint16_t type:4,
			 offset:12;
#else
		uint16_t offset:12,
			 type:4;
#endif
	    } fields;
	    uint16_t word;
	} u;
    } sb;

	host_byte_sex = get_host_byte_sex();
	to_host_byte_sex = (enum bool)(target_byte_sex == host_byte_sex);
	for(i = 0; i < n; i++){
	    if(to_host_byte_sex){
		memcpy(&sb, b + i, sizeof(struct base_relocation_entry));
		sb.u.word = SWAP_SHORT(sb.u.word);
		b[i].offset = sb.u.fields.offset;
		b[i].type = sb.u.fields.type;
	    }
	    else{
		sb.u.fields.offset = b[i].offset;
		sb.u.fields.type = b[i].type;
		sb.u.word = SWAP_SHORT(sb.u.word);
		memcpy(b + i, &sb, sizeof(struct base_relocation_entry));
	    }
	}
}

__private_extern__
void
swap_ms_dos_stub(
struct ms_dos_stub *m,
enum byte_sex target_byte_sex)
{
    int i;

	m->e_magic = SWAP_SHORT(m->e_magic);
	m->e_cblp = SWAP_SHORT(m->e_cblp);
	m->e_cp = SWAP_SHORT(m->e_cp);
	m->e_crlc = SWAP_SHORT(m->e_crlc);
	m->e_cparhdr = SWAP_SHORT(m->e_cparhdr);
	m->e_minalloc = SWAP_SHORT(m->e_minalloc);
	m->e_maxalloc = SWAP_SHORT(m->e_maxalloc);
	m->e_ss = SWAP_SHORT(m->e_ss);
	m->e_sp = SWAP_SHORT(m->e_sp);
	m->e_csum = SWAP_SHORT(m->e_csum);
	m->e_ip = SWAP_SHORT(m->e_ip);
	m->e_cs = SWAP_SHORT(m->e_cs);
	m->e_lfarlc = SWAP_SHORT(m->e_lfarlc);
	m->e_ovno = SWAP_SHORT(m->e_ovno);
	for(i = 0; i < 4; i++)
	    m->e_res[i] = SWAP_SHORT(m->e_res[i]);
	m->e_oemid = SWAP_SHORT(m->e_oemid);
	m->e_oeminfo = SWAP_SHORT(m->e_oeminfo);
	for(i = 0; i < 10; i++)
	    m->e_res2[i] = SWAP_SHORT(m->e_res2[i]);
	m->e_lfanew = SWAP_LONG(m->e_lfanew);
}

__private_extern__
void
swap_filehdr(
struct filehdr *f,
enum byte_sex target_byte_sex)
{
	f->f_magic = SWAP_SHORT(f->f_magic);
	f->f_nscns = SWAP_SHORT(f->f_nscns);
	f->f_timdat = SWAP_LONG(f->f_timdat);
	f->f_symptr = SWAP_LONG(f->f_symptr);
	f->f_nsyms = SWAP_LONG(f->f_nsyms);
	f->f_opthdr = SWAP_SHORT(f->f_opthdr);
	f->f_flags = SWAP_SHORT(f->f_flags);
}

__private_extern__
void
swap_aouthdr(
struct aouthdr *a,
enum byte_sex target_byte_sex)
{
    int i;

	a->magic = SWAP_SHORT(a->magic);
	a->vstamp = SWAP_SHORT(a->vstamp);
	a->tsize = SWAP_LONG(a->tsize);
	a->dsize = SWAP_LONG(a->dsize);
	a->bsize = SWAP_LONG(a->bsize);
	a->entry = SWAP_LONG(a->entry);
	a->text_start = SWAP_LONG(a->text_start);
	a->data_start = SWAP_LONG(a->data_start);
	a->ImageBase = SWAP_LONG(a->ImageBase);
	a->SectionAlignment = SWAP_LONG(a->SectionAlignment);
	a->FileAlignment = SWAP_LONG(a->FileAlignment);
	a->MajorOperatingSystemVersion =
		SWAP_SHORT(a->MajorOperatingSystemVersion);
	a->MinorOperatingSystemVersion =
		SWAP_SHORT(a->MinorOperatingSystemVersion);
	a->MajorImageVersion = SWAP_SHORT(a->MajorImageVersion);
	a->MinorImageVersion = SWAP_SHORT(a->MinorImageVersion);
	a->MajorSubsystemVersion = SWAP_SHORT(a->MajorSubsystemVersion);
	a->MinorSubsystemVersion = SWAP_SHORT(a->MinorSubsystemVersion);
	a->Win32VersionValue = SWAP_LONG(a->Win32VersionValue);
	a->SizeOfImage = SWAP_LONG(a->SizeOfImage);
	a->SizeOfHeaders = SWAP_LONG(a->SizeOfHeaders);
	a->CheckSum = SWAP_LONG(a->CheckSum);
	a->Subsystem = SWAP_SHORT(a->Subsystem);
	a->DllCharacteristics = SWAP_SHORT(a->DllCharacteristics);
	a->SizeOfStackReserve = SWAP_LONG(a->SizeOfStackReserve);
	a->SizeOfStackCommit = SWAP_LONG(a->SizeOfStackCommit);
	a->SizeOfHeapReserve = SWAP_LONG(a->SizeOfHeapReserve);
	a->SizeOfHeapCommit = SWAP_LONG(a->SizeOfHeapCommit);
	a->LoaderFlags = SWAP_LONG(a->LoaderFlags);
	a->NumberOfRvaAndSizes = SWAP_LONG(a->NumberOfRvaAndSizes);
	for(i = 0; i < 16; i++){
	    a->DataDirectory[i][0] = SWAP_LONG(a->DataDirectory[i][0]);
	    a->DataDirectory[i][1] = SWAP_LONG(a->DataDirectory[i][1]);
	}
}

__private_extern__
void
swap_aouthdr_64(
struct aouthdr_64 *a,
enum byte_sex target_byte_sex)
{
    int i;

	a->magic = SWAP_SHORT(a->magic);
	a->vstamp = SWAP_SHORT(a->vstamp);
	a->tsize = SWAP_LONG(a->tsize);
	a->dsize = SWAP_LONG(a->dsize);
	a->bsize = SWAP_LONG(a->bsize);
	a->entry = SWAP_LONG(a->entry);
	a->text_start = SWAP_LONG(a->text_start);
	a->ImageBase = SWAP_LONG_LONG(a->ImageBase);
	a->SectionAlignment = SWAP_LONG(a->SectionAlignment);
	a->FileAlignment = SWAP_LONG(a->FileAlignment);
	a->MajorOperatingSystemVersion =
		SWAP_SHORT(a->MajorOperatingSystemVersion);
	a->MinorOperatingSystemVersion =
		SWAP_SHORT(a->MinorOperatingSystemVersion);
	a->MajorImageVersion = SWAP_SHORT(a->MajorImageVersion);
	a->MinorImageVersion = SWAP_SHORT(a->MinorImageVersion);
	a->MajorSubsystemVersion = SWAP_SHORT(a->MajorSubsystemVersion);
	a->MinorSubsystemVersion = SWAP_SHORT(a->MinorSubsystemVersion);
	a->Win32VersionValue = SWAP_LONG(a->Win32VersionValue);
	a->SizeOfImage = SWAP_LONG(a->SizeOfImage);
	a->SizeOfHeaders = SWAP_LONG(a->SizeOfHeaders);
	a->CheckSum = SWAP_LONG(a->CheckSum);
	a->Subsystem = SWAP_SHORT(a->Subsystem);
	a->DllCharacteristics = SWAP_SHORT(a->DllCharacteristics);
	a->SizeOfStackReserve = SWAP_LONG_LONG(a->SizeOfStackReserve);
	a->SizeOfStackCommit = SWAP_LONG_LONG(a->SizeOfStackCommit);
	a->SizeOfHeapReserve = SWAP_LONG_LONG(a->SizeOfHeapReserve);
	a->SizeOfHeapCommit = SWAP_LONG(a->SizeOfHeapCommit);
	a->LoaderFlags = SWAP_LONG(a->LoaderFlags);
	a->NumberOfRvaAndSizes = SWAP_LONG(a->NumberOfRvaAndSizes);
	for(i = 0; i < 16; i++){
	    a->DataDirectory[i][0] = SWAP_LONG(a->DataDirectory[i][0]);
	    a->DataDirectory[i][1] = SWAP_LONG(a->DataDirectory[i][1]);
	}
}

__private_extern__
void
swap_scnhdr(
struct scnhdr *s,
uint32_t n,
enum byte_sex target_byte_sex)
{
    uint32_t i;

	for(i = 0; i < n; i++){
	    s[i].s_vsize = SWAP_LONG(s[i].s_vsize);
	    s[i].s_vaddr = SWAP_LONG(s[i].s_vaddr);
	    s[i].s_size = SWAP_LONG(s[i].s_size);
	    s[i].s_scnptr = SWAP_LONG(s[i].s_scnptr);
	    s[i].s_relptr = SWAP_LONG(s[i].s_relptr);
	    s[i].s_lnnoptr = SWAP_LONG(s[i].s_lnnoptr);
	    s[i].s_nreloc = SWAP_SHORT(s[i].s_nreloc);
	    s[i].s_nlnno = SWAP_SHORT(s[i].s_nlnno);
	    s[i].s_flags = SWAP_LONG(s[i].s_flags);
	}
}

__private_extern__
void
swap_syment(
struct syment *s,
uint32_t n,
enum byte_sex target_byte_sex)
{
    uint32_t i;

	for(i = 0; i < n; i++){
	    if(s[i].e.e.e_zeroes == 0)
		s[i].e.e.e_offset = SWAP_LONG(s[i].e.e.e_offset);
	    s[i].e_value = SWAP_LONG(s[i].e_value);
	    s[i].e_scnum = SWAP_SHORT(s[i].e_scnum);
	    s[i].e_type = SWAP_SHORT(s[i].e_type);
	}
}
