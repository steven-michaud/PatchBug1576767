/* The MIT License (MIT)
 *
 * Copyright (c) 2020 Steven Michaud
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// PatchBug1576767.kext is a kernel extension that patches running kernel
// extension code on macOS Catalina to work around an Apple bug that causes
// most of the crashes reported at Mozilla bug 1576767
// (https://bugzilla.mozilla.org/show_bug.cgi?id=1576767). Loading
// PatchBug1576767.kext patches code at two different locations in the
// running AMDRadeonX4000 kernel extension (or AMDRadeonX5000, or
// AMDRadeonX6000, whichever is in use). Unloading it restores the code to its
// original (buggy) state. PatchBug1576767.kext only works on macOS Catalina,
// minor version 4 or above. (It fails to load on other versions of macOS.) It
// also requires that you include "keepsyms=1" among your kernel boot args.
// (Otherwise it will load, but fail to patch the code.)
//
// PatchBug1576767.kext is intended as proof on concept, to show people who
// experience bug 1576767 that their crashes are actually caused by an Apple
// bug. It's also intended as a temporary workaround until Apple fixes the
// bug.

// Apple only supports a subset of C/C++ for kernel extensions. Apple
// documents some of the features which are disallowed[1], but not all of
// them. Apple's list of disallowed features includes exceptions, multiple
// inheritance, templates and RTTI. But complex initialization of local
// variables is also disallowed -- for example structure initialization and
// variable initialization in a "for" statement (e.g. "for (int i = 1; ; )").
// You won't always get a compiler warning if you use one of these disallowed
// features. And you may not always see problems using the resulting binary.
// But in at least some cases you will see mysterious kernel panics.
//
// [1]https://developer.apple.com/library/mac/documentation/DeviceDrivers/Conceptual/IOKitFundamentals/Features/Features.html#//apple_ref/doc/uid/TP0000012-TPXREF105

#include <libkern/libkern.h>

#include <AvailabilityMacros.h>

#include <sys/sysctl.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <libkern/OSAtomic.h>
#include <i386/proc_reg.h>

#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSSerialize.h>
#include <IOKit/IOLib.h>

#include "PatchBug1576767.h"

extern "C" int atoi(const char *str);

typedef struct pmap *pmap_t;
extern pmap_t kernel_pmap;

extern "C" void vm_kernel_unslide_or_perm_external(vm_offset_t addr,
                                                   vm_offset_t *up_addr);

extern "C" ppnum_t pmap_find_phys(pmap_t map, addr64_t va);

/*------------------------------*/

// "kern.osrelease" is what's returned by 'uname -r', which uses a different
// numbering system than the "standard" one. These defines translate from
// that (kernel) system to the "standard" one.

#define MAC_OS_X_VERSION_10_9_HEX  0x00000D00
#define MAC_OS_X_VERSION_10_10_HEX 0x00000E00
#define MAC_OS_X_VERSION_10_11_HEX 0x00000F00
#define MAC_OS_X_VERSION_10_12_HEX 0x00001000
#define MAC_OS_X_VERSION_10_13_HEX 0x00001100
#define MAC_OS_X_VERSION_10_14_HEX 0x00001200
#define MAC_OS_X_VERSION_10_15_HEX 0x00001300

char *gOSVersionString = NULL;
size_t gOSVersionStringLength = 0;

int32_t OSX_Version()
{
  static int32_t version = -1;
  if (version != -1) {
    return version;
  }

  version = 0;
  sysctlbyname("kern.osrelease", NULL, &gOSVersionStringLength, NULL, 0);
  gOSVersionString = (char *) IOMalloc(gOSVersionStringLength);
  char *version_string = (char *) IOMalloc(gOSVersionStringLength);
  if (!gOSVersionString || !version_string) {
    return version;
  }
  if (sysctlbyname("kern.osrelease", gOSVersionString,
                   &gOSVersionStringLength, NULL, 0) < 0)
  {
    IOFree(version_string, gOSVersionStringLength);
    return version;
  }
  strncpy(version_string, gOSVersionString, gOSVersionStringLength);

  char *version_string_iterator = version_string;
  const char *part; int i;
  for (i = 0; i < 3; ++i) {
    part = strsep(&version_string_iterator, ".");
    if (!part) {
      break;
    }
    version += (atoi(part) << ((2 - i) * 4));
  }

  IOFree(version_string, gOSVersionStringLength);
  return version;
}

bool macOS_Catalina()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_15_HEX);
}

bool macOS_Catalina_at_least_4()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_15_HEX)) {
    return false;
  }
  return ((OSX_Version() & 0xFF) >= 0x40);
}

bool OSX_Version_Unsupported()
{
  return !macOS_Catalina_at_least_4();
}

#define VM_MIN_KERNEL_ADDRESS ((vm_offset_t) 0xFFFFFF8000000000UL)
#define VM_MIN_KERNEL_AND_KEXT_ADDRESS (VM_MIN_KERNEL_ADDRESS - 0x80000000ULL)
#define VM_MAX_USER_PAGE_ADDRESS ((user_addr_t)0x00007FFFFFFFF000ULL)

// The system kernel (stored in /System/Library/Kernels on OS X 10.10 and up)
// is (in some senses) an ordinary Mach-O binary. You can use 'otool -hv' to
// show its Mach header, and 'otool -lv' to display its "load commands" (all
// of its segments and sections). From the output of 'otool -lv' it's
// apparent that the kernel (starting with its Mach header) is meant to be
// loaded at 0xFFFFFF8000200000. But recent versions of OS X implement ASLR
// (Address Space Layout Randomization) for the kernel -- they "slide" all
// kernel addresses by a random value (determined at startup). So in order
// to find the address of the kernel (and of its Mach header), we also need to
// know the value of this "kernel slide".

#define KERNEL_HEADER_ADDR 0xFFFFFF8000200000

vm_offset_t g_kernel_slide = 0;
struct mach_header_64 *g_kernel_header = NULL;

// Find the address of the kernel's Mach header.
bool find_kernel_header()
{
  if (g_kernel_header) {
    return true;
  }

#if (defined(MAC_OS_X_VERSION_10_11)) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) >= (MAC_OS_X_VERSION_10_11 / 100)
  // vm_kernel_unslide_or_perm_external() is only available on OS X 10.11 and up.
  if (macOS_Catalina()) {
    vm_offset_t func_address = (vm_offset_t) vm_kernel_unslide_or_perm_external;
    vm_offset_t func_address_unslid = 0;
    vm_kernel_unslide_or_perm_external(func_address, &func_address_unslid);
    g_kernel_slide = func_address - func_address_unslid;
  } else {
#endif
    bool kernel_header_found = false;
    vm_offset_t slide;
    // The 0x10000 increment was determined by trial and error.
    for (slide = 0; slide < 0x100000000; slide += 0x10000) {
      addr64_t addr = KERNEL_HEADER_ADDR + slide;
      // pmap_find_phys() returns 0 if 'addr' isn't a valid address.
      if (!pmap_find_phys(kernel_pmap, addr)) {
        continue;
      }
      struct mach_header_64 *header = (struct mach_header_64 *) addr;
      if ((header->magic != MH_MAGIC_64) ||
          (header->cputype != CPU_TYPE_X86_64 ) ||
          (header->cpusubtype != CPU_SUBTYPE_I386_ALL) ||
          (header->filetype != MH_EXECUTE) ||
          (header->flags != (MH_NOUNDEFS | MH_PIE)))
      {
        continue;
      }
      g_kernel_slide = slide;
      kernel_header_found = true;
      break;
    }
    if (!kernel_header_found) {
      return false;
    }
#if (defined(MAC_OS_X_VERSION_10_11)) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) >= (MAC_OS_X_VERSION_10_11 / 100)
  }
#endif

  g_kernel_header = (struct mach_header_64 *)
    (KERNEL_HEADER_ADDR + g_kernel_slide);

  return true;
}

// Fill the whole structure with 0xFF to indicate that it hasn't yet been
// initialized.
typedef struct _symbol_table_info {
  vm_offset_t symbolTableOffset;
  vm_offset_t stringTableOffset;
  uint32_t symbols_index;
  uint32_t symbols_count;
} symbol_table_info_t;

void *kernel_module_dlsym(struct mach_header_64 *header, const char *symbol,
                          symbol_table_info_t *info)
{
  if (!header || !symbol) {
    return NULL;
  }

  // Sanity check
  if (!pmap_find_phys(kernel_pmap, (addr64_t) header)) {
    return NULL;
  }
  if ((header->magic != MH_MAGIC_64) ||
      (header->cputype != CPU_TYPE_X86_64) ||
      (header->cpusubtype != CPU_SUBTYPE_I386_ALL) ||
      ((header->filetype != MH_EXECUTE) &&
       (header->filetype != MH_KEXT_BUNDLE)) ||
      ((header->flags & MH_NOUNDEFS) == 0))
  {
    return NULL;
  }

  vm_offset_t symbolTableOffset = 0;
  vm_offset_t stringTableOffset = 0;
  uint32_t symbols_index = 0;
  uint32_t symbols_count = 0;
  uint32_t all_symbols_count = 0;

  // Find the symbol table, if need be
  if (info && info->symbolTableOffset != -1L) {
    symbolTableOffset = info->symbolTableOffset;
    stringTableOffset = info->stringTableOffset;
    symbols_index = info->symbols_index;
    symbols_count = info->symbols_count;
  } else {
    vm_offset_t linkedit_fileoff_increment = 0;
    bool found_symbol_table = false;
    bool found_linkedit_segment = false;
    bool found_symtab_segment = false;
    bool found_dysymtab_segment = false;
    uint32_t num_commands = header->ncmds;
    const struct load_command *load_command = (struct load_command *)
      ((vm_offset_t)header + sizeof(struct mach_header_64));
    uint32_t i;
    for (i = 1; i <= num_commands; ++i) {
      uint32_t cmd = load_command->cmd;
      switch (cmd) {
        case LC_SEGMENT_64: {
          if (found_linkedit_segment) {
            return NULL;
          }
          struct segment_command_64 *command =
            (struct segment_command_64 *) load_command;
          if (!strcmp(command->segname, "__LINKEDIT")) {
            linkedit_fileoff_increment = command->vmaddr - command->fileoff;
            found_linkedit_segment = true;
          }
          break;
        }
        case LC_SYMTAB: {
          if (!found_linkedit_segment) {
            return NULL;
          }
          struct symtab_command *command =
            (struct symtab_command *) load_command;
          symbolTableOffset = command->symoff + linkedit_fileoff_increment;
          stringTableOffset = command->stroff + linkedit_fileoff_increment;
          all_symbols_count = command->nsyms;
          found_symtab_segment = true;
          break;
        }
        case LC_DYSYMTAB: {
          if (!found_linkedit_segment) {
            return NULL;
          }
          struct dysymtab_command *command =
            (struct dysymtab_command *) load_command;
          // It seems that either LC_SYMTAB's nsyms will be set or LC_DSYMTAB's
          // iextdefsym and nextdefsym, but not both. Loaded kexts use nsyms,
          // but the kernel itself uses iextdefsym and nextdefsym.
          if (all_symbols_count) {
            symbols_index = 0;
            symbols_count = all_symbols_count;
          } else {
            symbols_index = command->iextdefsym;
            symbols_count = symbols_index + command->nextdefsym;
          }
          found_dysymtab_segment = true;
          break;
        }
        default: {
          if (found_linkedit_segment) {
            return NULL;
          }
          break;
        }
      }
      if (found_linkedit_segment && found_symtab_segment && found_dysymtab_segment) {
        found_symbol_table = true;
        break;
      }
      load_command = (struct load_command *)
        ((vm_offset_t)load_command + load_command->cmdsize);
    }
    if (!found_symbol_table) {
      return NULL;
    }
    if (info) {
      info->symbolTableOffset = symbolTableOffset;
      info->stringTableOffset = stringTableOffset;
      info->symbols_index = symbols_index;
      info->symbols_count = symbols_count;
    }
  }

  // If we're in a kernel extension, the symbol and string tables won't be
  // accessible unless the "keepsyms=1" kernel boot arg has been specified.
  // Use this check to fail gracefully in this situation.
  if (!pmap_find_phys(kernel_pmap, (addr64_t) symbolTableOffset) ||
      !pmap_find_phys(kernel_pmap, (addr64_t) stringTableOffset))
  {
    return NULL;
  }
  // Search the symbol table
  uint32_t i;
  for (i = symbols_index; i < symbols_count; ++i) {
    struct nlist_64 *symbolTableItem = (struct nlist_64 *)
      (symbolTableOffset + i * sizeof(struct nlist_64));

    uint8_t type = symbolTableItem->n_type;
    if ((type & N_STAB) || ((type & N_TYPE) != N_SECT)) {
      continue;
    }
    uint8_t sect = symbolTableItem->n_sect;
    if (!sect) {
      continue;
    }
    const char *stringTableItem = (char *)
      (stringTableOffset + symbolTableItem->n_un.n_strx);
    if (stringTableItem && !strcmp(stringTableItem, symbol)) {
      return (void *) symbolTableItem->n_value;
    }
  }

  return NULL;
}

// The running kernel contains a valid symbol table. We can use this to find
// the address of any "external" kernel symbol, including those considered
// "private". 'symbol' should be exactly what's listed in the symbol table,
// including the "extra" leading underscore.
void *kernel_dlsym(const char *symbol)
{
  if (!find_kernel_header()) {
    return NULL;
  }

  static symbol_table_info_t kernel_symbol_info;
  static bool found_symbol_table = false;
  if (!found_symbol_table) {
    memset((void *) &kernel_symbol_info, 0xFF, sizeof(kernel_symbol_info));
  }

  void *retval =
    kernel_module_dlsym(g_kernel_header, symbol, &kernel_symbol_info);

  if (kernel_symbol_info.symbolTableOffset != -1L) {
    found_symbol_table = true;
  }

  return retval;
}

typedef OSDictionary *(*OSKext_copyLoadedKextInfo_t)(OSArray *kextIdentifiers,
                                              OSArray *infoKeys);
static OSKext_copyLoadedKextInfo_t OSKext_copyLoadedKextInfo = NULL;

#define kOSBundleLoadAddressKey "OSBundleLoadAddress"

// Loaded kernel extensions also contain valid symbol tables. But unless the
// "keepsyms=1" kernel boot arg has been specified, they have been made
// inaccessible in OSKext::jettisonLinkeditSegment().
void *kext_dlsym(const char *bundle_id, const char *symbol)
{
  if (!OSKext_copyLoadedKextInfo) {
    OSKext_copyLoadedKextInfo = (OSKext_copyLoadedKextInfo_t)
      kernel_dlsym("__ZN6OSKext18copyLoadedKextInfoEP7OSArrayS1_");
    if (!OSKext_copyLoadedKextInfo) {
      return NULL;
    }
  }

  if (!bundle_id || !symbol) {
    return NULL;
  }

  const OSString *id_string = OSString::withCString(bundle_id);
  if (!id_string) {
    return NULL;
  }
  OSArray *id_array =
    OSArray::withObjects((const OSObject **) &id_string, 1, 0);
  if (!id_array) {
    id_string->release();
    return NULL;
  }
  OSDictionary *kext_info =
    OSDynamicCast(OSDictionary, OSKext_copyLoadedKextInfo(id_array, 0));
  if (!kext_info) {
    id_string->release();
    id_array->release();
    return NULL;
  }
  OSNumber *load_address =
    OSDynamicCast(OSNumber, kext_info->getObject(kOSBundleLoadAddressKey));
  if (!load_address) {
    OSDictionary *more_kext_info =
      OSDynamicCast(OSDictionary, kext_info->getObject(bundle_id));
    kext_info = more_kext_info;
    if (kext_info) {
      load_address =
        OSDynamicCast(OSNumber, kext_info->getObject(kOSBundleLoadAddressKey));
    }
  }
  if (!load_address) {
    id_string->release();
    id_array->release();
    return NULL;
  }

  struct mach_header_64 *kext_header = (struct mach_header_64 *)
    (load_address->unsigned64BitValue() + g_kernel_slide);

  void *retval = kernel_module_dlsym(kext_header, symbol, NULL);

  id_string->release();
  id_array->release();

  return retval;
}

typedef void (*disable_preemption_t)(void);
typedef void (*enable_preemption_t)(void);
static disable_preemption_t disable_preemption = NULL;
static enable_preemption_t enable_preemption = NULL;

bool s_kernel_private_functions_found = false;

bool find_kernel_private_functions()
{
  if (s_kernel_private_functions_found) {
    return true;
  }

  if (!disable_preemption) {
    disable_preemption = (disable_preemption_t)
      kernel_dlsym("__disable_preemption");
    if (!disable_preemption) {
      return false;
    }
  }
  if (!enable_preemption) {
    enable_preemption = (enable_preemption_t)
      kernel_dlsym("__enable_preemption");
    if (!enable_preemption) {
      return false;
    }
  }

  s_kernel_private_functions_found = true;
  return true;
}

// The first two bytes of a JAE rel32 instruction.
// unsigned char[] = {0x0f, 0x83} when stored in little endian format
#define JAE_REL32_BEGIN_SHORT 0x830f

// The first two bytes of a JA rel32 instruction.
// unsigned char[] = {0x0f, 0x87} when stored in little endian format
#define JA_REL32_BEGIN_SHORT 0x870f

unsigned char *AMDRadeonX4000_mapVA = NULL;
unsigned char *AMDRadeonX5000_mapVA = NULL;
unsigned char *AMDRadeonX6000_mapVA = NULL;
unsigned char *AMDRadeonX4000_unmapVA = NULL;
unsigned char *AMDRadeonX5000_unmapVA = NULL;
unsigned char *AMDRadeonX6000_unmapVA = NULL;

#define AMDRadeonX4000_MAPVA_JAE_OFFSET 0x30
#define AMDRadeonX5000_MAPVA_JAE_OFFSET 0x30
#define AMDRadeonX6000_MAPVA_JAE_OFFSET 0x2c
#define AMDRadeonX4000_UNMAPVA_JAE_OFFSET 0x2c
#define AMDRadeonX5000_UNMAPVA_JAE_OFFSET 0x2c
#define AMDRadeonX6000_UNMAPVA_JAE_OFFSET 0x2d

uint32_t AMDRadeonX4000_mapVA_jae = 0;
uint32_t AMDRadeonX5000_mapVA_jae = 0;
uint32_t AMDRadeonX6000_mapVA_jae = 0;
uint32_t AMDRadeonX4000_unmapVA_jae = 0;
uint32_t AMDRadeonX5000_unmapVA_jae = 0;
uint32_t AMDRadeonX6000_unmapVA_jae = 0;

bool patch_bad_instructions()
{
  if (AMDRadeonX4000_mapVA_jae || AMDRadeonX5000_mapVA_jae ||
      AMDRadeonX6000_mapVA_jae || AMDRadeonX4000_unmapVA_jae ||
      AMDRadeonX5000_unmapVA_jae || AMDRadeonX6000_unmapVA_jae)
  {
    return true;
  }

  if (!find_kernel_private_functions()) {
    return false;
  }

  if (!AMDRadeonX4000_mapVA) {
    AMDRadeonX4000_mapVA = (unsigned char *) kext_dlsym("com.apple.kext.AMDRadeonX4000",
      "__ZN29AMDRadeonX4000_AMDHWVMContext5mapVAEyP13IOAccelMemoryyyN24AMDRadeonX4000_IAMDHWVMM10VmMapFlagsE");
  }
  if (!AMDRadeonX5000_mapVA) {
    AMDRadeonX5000_mapVA = (unsigned char *) kext_dlsym("com.apple.kext.AMDRadeonX5000",
      "__ZN29AMDRadeonX5000_AMDHWVMContext5mapVAEyP13IOAccelMemoryyyN24AMDRadeonX5000_IAMDHWVMM10VmMapFlagsE");
  }
  if (!AMDRadeonX6000_mapVA) {
    AMDRadeonX6000_mapVA = (unsigned char *) kext_dlsym("com.apple.kext.AMDRadeonX6000",
      "__ZN29AMDRadeonX6000_AMDHWVMContext5mapVAEyP13IOAccelMemoryyyN24AMDRadeonX6000_IAMDHWVMM10VmMapFlagsE");
  }
  if (!AMDRadeonX4000_mapVA && !AMDRadeonX5000_mapVA && !AMDRadeonX6000_mapVA) {
    kprintf("HookCase: patch_bad_instructions(): No AMDHWVMContext::mapVA() functions found\n");
    return false;
  }
  if (!AMDRadeonX4000_unmapVA) {
    AMDRadeonX4000_unmapVA = (unsigned char *) kext_dlsym("com.apple.kext.AMDRadeonX4000",
      "__ZN29AMDRadeonX4000_AMDHWVMContext7unmapVAEyy");
  }
  if (!AMDRadeonX5000_unmapVA) {
    AMDRadeonX5000_unmapVA = (unsigned char *) kext_dlsym("com.apple.kext.AMDRadeonX5000",
      "__ZN29AMDRadeonX5000_AMDHWVMContext7unmapVAEyy");
  }
  if (!AMDRadeonX6000_unmapVA) {
    AMDRadeonX6000_unmapVA = (unsigned char *) kext_dlsym("com.apple.kext.AMDRadeonX6000",
      "__ZN29AMDRadeonX6000_AMDHWVMContext7unmapVAEyy");
  }
  if (!AMDRadeonX4000_unmapVA && !AMDRadeonX5000_unmapVA && !AMDRadeonX6000_unmapVA) {
    kprintf("HookCase: patch_bad_instructions(): No AMDHWVMContext::unmapVA() functions found\n");
    return false;
  }

  uint32_t i;
  uint32_t num_patched = 0;
  for (i = 4; i < 7; ++i) {
    unsigned char *mapVA = NULL;
    unsigned char *unmapVA = NULL;
    uint32_t *mapVA_jae = NULL;
    uint32_t *unmapVA_jae = NULL;
    uint32_t map_jae_offset = 0;
    uint32_t unmap_jae_offset = 0;
    switch (i) {
      case 4: {
        mapVA = AMDRadeonX4000_mapVA;
        unmapVA = AMDRadeonX4000_unmapVA;
        mapVA_jae = &AMDRadeonX4000_mapVA_jae;
        unmapVA_jae = &AMDRadeonX4000_unmapVA_jae;
        map_jae_offset = AMDRadeonX4000_MAPVA_JAE_OFFSET;
        unmap_jae_offset = AMDRadeonX4000_UNMAPVA_JAE_OFFSET;
        break;
      }
      case 5: {
        mapVA = AMDRadeonX5000_mapVA;
        unmapVA = AMDRadeonX5000_unmapVA;
        mapVA_jae = &AMDRadeonX5000_mapVA_jae;
        unmapVA_jae = &AMDRadeonX5000_unmapVA_jae;
        map_jae_offset = AMDRadeonX5000_MAPVA_JAE_OFFSET;
        unmap_jae_offset = AMDRadeonX5000_UNMAPVA_JAE_OFFSET;
        break;
      }
      case 6: {
        mapVA = AMDRadeonX6000_mapVA;
        unmapVA = AMDRadeonX6000_unmapVA;
        mapVA_jae = &AMDRadeonX6000_mapVA_jae;
        unmapVA_jae = &AMDRadeonX6000_unmapVA_jae;
        map_jae_offset = AMDRadeonX6000_MAPVA_JAE_OFFSET;
        unmap_jae_offset = AMDRadeonX6000_UNMAPVA_JAE_OFFSET;
        break;
      }
      default:
        return false;
    }

    if (!mapVA || !unmapVA) {
      continue;
    }

    uint32_t j;
    for (j = 0; j < 2; ++j) {
      unsigned char *function = NULL;
      uint32_t *function_jae = NULL;
      uint32_t function_jae_offset = 0;
      char function_name[256];
      switch (j) {
        case 0: {
          function = mapVA;
          function_jae = mapVA_jae;
          function_jae_offset = map_jae_offset;
          snprintf(function_name, sizeof(function_name),
                   "AMDRadeonX%u000_AMDHWVMContext::mapVA()", i);
          break;
        }
        case 1: {
          function = unmapVA;
          function_jae = unmapVA_jae;
          function_jae_offset = unmap_jae_offset;
          snprintf(function_name, sizeof(function_name),
                   "AMDRadeonX%u000_AMDHWVMContext::unmapVA()", i);
          break;
        }
        default:
          return false;
      }

      uint32_t *target = (uint32_t *) (function + function_jae_offset);
      function_jae[0] = target[0];

      // Sanity check
      if ((function_jae[0] & 0xffff) != JAE_REL32_BEGIN_SHORT) {
        kprintf("PatchBug1576767: patch_bad_instructions(): Unexpected instruction at offset 0x%x in %s\n",
                function_jae_offset, function_name);
        function_jae[0] = 0;
        continue;
      }

      bool retval = true;

      uint32_t new_instruction = function_jae[0];
      new_instruction &= 0xffff0000;
      new_instruction |= JA_REL32_BEGIN_SHORT;

      boolean_t org_int_level = ml_set_interrupts_enabled(false);
      disable_preemption();
      uintptr_t org_cr0 = get_cr0();
      set_cr0(org_cr0 & ~CR0_WP);

      if (!OSCompareAndSwap(function_jae[0], new_instruction, target)) {
        retval = false;
      }

      set_cr0(org_cr0);
      enable_preemption();
      ml_set_interrupts_enabled(org_int_level);

      if (retval) {
        kprintf("PatchBug1576767: patch_bad_instructions(): %s patched\n", function_name);
        ++num_patched;
      } else {
        kprintf("PatchBug1576767: patch_bad_instructions(): OSCompareAndSwap() failed on %s\n",
                function_name);
        function_jae[0] = 0;
      }
    }
  }

  if (!num_patched) {
    kprintf("PatchBug1576767: patch_bad_instructions(): Failed\n");
    return false;
  }

  return true;
}

bool restore_bad_instructions()
{
  if (!AMDRadeonX4000_mapVA_jae && !AMDRadeonX5000_mapVA_jae &&
      !AMDRadeonX6000_mapVA_jae && !AMDRadeonX4000_unmapVA_jae &&
      !AMDRadeonX5000_unmapVA_jae && !AMDRadeonX6000_unmapVA_jae)
  {
    return true;
  }

  if (!find_kernel_private_functions()) {
    return false;
  }

  uint32_t i;
  uint32_t num_unpatched = 0;
  for (i = 4; i < 7; ++i) {
    unsigned char *mapVA = NULL;
    unsigned char *unmapVA = NULL;
    uint32_t *mapVA_jae = NULL;
    uint32_t *unmapVA_jae = NULL;
    uint32_t map_jae_offset = 0;
    uint32_t unmap_jae_offset = 0;
    switch (i) {
      case 4: {
        mapVA = AMDRadeonX4000_mapVA;
        unmapVA = AMDRadeonX4000_unmapVA;
        mapVA_jae = &AMDRadeonX4000_mapVA_jae;
        unmapVA_jae = &AMDRadeonX4000_unmapVA_jae;
        map_jae_offset = AMDRadeonX4000_MAPVA_JAE_OFFSET;
        unmap_jae_offset = AMDRadeonX4000_UNMAPVA_JAE_OFFSET;
        break;
      }
      case 5: {
        mapVA = AMDRadeonX5000_mapVA;
        unmapVA = AMDRadeonX5000_unmapVA;
        mapVA_jae = &AMDRadeonX5000_mapVA_jae;
        unmapVA_jae = &AMDRadeonX5000_unmapVA_jae;
        map_jae_offset = AMDRadeonX5000_MAPVA_JAE_OFFSET;
        unmap_jae_offset = AMDRadeonX5000_UNMAPVA_JAE_OFFSET;
        break;
      }
      case 6: {
        mapVA = AMDRadeonX6000_mapVA;
        unmapVA = AMDRadeonX6000_unmapVA;
        mapVA_jae = &AMDRadeonX6000_mapVA_jae;
        unmapVA_jae = &AMDRadeonX6000_unmapVA_jae;
        map_jae_offset = AMDRadeonX6000_MAPVA_JAE_OFFSET;
        unmap_jae_offset = AMDRadeonX6000_UNMAPVA_JAE_OFFSET;
        break;
      }
      default:
        return false;
    }

    if (!mapVA || !mapVA_jae[0] || !unmapVA || !unmapVA_jae[0]) {
      continue;
    }

    uint32_t j;
    for (j = 0; j < 2; ++j) {
      unsigned char *function = NULL;
      uint32_t *function_jae = NULL;
      uint32_t function_jae_offset = 0;
      char function_name[256];
      switch (j) {
        case 0: {
          function = mapVA;
          function_jae = mapVA_jae;
          function_jae_offset = map_jae_offset;
          snprintf(function_name, sizeof(function_name),
                   "AMDRadeonX%u000_AMDHWVMContext::mapVA()", i);
          break;
        }
        case 1: {
          function = unmapVA;
          function_jae = unmapVA_jae;
          function_jae_offset = unmap_jae_offset;
          snprintf(function_name, sizeof(function_name),
                   "AMDRadeonX%u000_AMDHWVMContext::unmapVA()", i);
          break;
        }
        default:
          return false;
      }

      uint32_t *target = (uint32_t *) (function + function_jae_offset);
      uint32_t current_value = target[0];

      bool retval = true;

      boolean_t org_int_level = ml_set_interrupts_enabled(false);
      disable_preemption();
      uintptr_t org_cr0 = get_cr0();
      set_cr0(org_cr0 & ~CR0_WP);

      if (!OSCompareAndSwap(current_value, function_jae[0], target)) {
        retval = false;
      }

      set_cr0(org_cr0);
      enable_preemption();
      ml_set_interrupts_enabled(org_int_level);

      if (retval) {
        kprintf("PatchBug1576767: patch_restored_instructions(): %s restored\n", function_name);
        function_jae[0] = 0;
        ++num_unpatched;
      } else {
        kprintf("PatchBug1576767: patch_restore_instructions(): OSCompareAndSwap() failed on %s\n",
                function_name);
      }
    }
  }

  if (!num_unpatched) {
    kprintf("PatchBug1576767: restore_bad_instructions(): Failed\n");
    return false;
  }

  return true;
}

extern "C" kern_return_t PatchBug1576767_start(kmod_info_t * ki, void *d);
extern "C" kern_return_t PatchBug1576767_stop(kmod_info_t *ki, void *d);

kern_return_t PatchBug1576767_start(kmod_info_t * ki, void *d)
{
  if (OSX_Version_Unsupported()) {
    kprintf("PatchBug1576767 requires macOS Catalina, minor version 10.15.4 or above: current version %s\n",
            gOSVersionString ? gOSVersionString : "null");
    if (gOSVersionString) {
      IOFree(gOSVersionString, gOSVersionStringLength);
    }
    return KERN_NOT_SUPPORTED;
  }

  patch_bad_instructions();

  return KERN_SUCCESS;
}

kern_return_t PatchBug1576767_stop(kmod_info_t *ki, void *d)
{
  if (!OSX_Version_Unsupported()) {
    restore_bad_instructions();
  }
  return KERN_SUCCESS;
}
