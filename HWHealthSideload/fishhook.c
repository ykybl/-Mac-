// Copyright (c) 2013, Facebook, Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name Facebook nor the names of its contributors may be used to
//     endorse or promote products derived from this software without specific
//     prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "fishhook.h"

#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif

struct RebindingsEntry {
  struct Rebinding *rebindings;
  size_t rebindings_nel;
  struct RebindingsEntry *next;
};

static struct RebindingsEntry *_rebindingsHead;

static int prepend_rebindings(struct RebindingsEntry **rebindings_head,
                              struct Rebinding rebindings[],
                              size_t nel) {
  struct RebindingsEntry *new_entry = (struct RebindingsEntry *) malloc(sizeof(struct RebindingsEntry));
  if (!new_entry) {
    return -1;
  }
  new_entry->rebindings = (struct Rebinding *) malloc(sizeof(struct Rebinding) * nel);
  if (!new_entry->rebindings) {
    free(new_entry);
    return -1;
  }
  memcpy(new_entry->rebindings, rebindings, sizeof(struct Rebinding) * nel);
  new_entry->rebindings_nel = nel;
  new_entry->next = *rebindings_head;
  *rebindings_head = new_entry;
  return 0;
}

#if 0
static int get_protection(void *addr, vm_prot_t *prot, vm_prot_t *max_prot) {
  mach_port_t task = mach_task_self();
  vm_size_t size = 0;
  vm_address_t address = (vm_address_t)addr;
  memory_object_name_t object;
#ifdef __LP64__
  mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
  vm_region_basic_info_data_64_t info;
  kern_return_t info_ret = vm_region_64(
      task, &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_64_t)&info, &count, &object);
#else
  mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT;
  vm_region_basic_info_data_t info;
  kern_return_t info_ret = vm_region(task, &address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &count, &object);
#endif
  if (info_ret == KERN_SUCCESS) {
    if (prot != NULL)
      *prot = info.protection;

    if (max_prot != NULL)
      *max_prot = info.max_protection;

    return 0;
  }

  return -1;
}
#endif

static bool check_and_apply_rebinding(struct RebindingsEntry *entry,
                                      const char *symbol_name,
                                      void **binding_addr,
                                      size_t section_size) {
  for (uint j = 0; j < entry->rebindings_nel; j++) {
    if (strcmp(&symbol_name[1], entry->rebindings[j].name) == 0) {
      if (entry->rebindings[j].replaced != NULL && *binding_addr != entry->rebindings[j].replacement) {
        *(entry->rebindings[j].replaced) = *binding_addr;
      }
      kern_return_t err = vm_protect(mach_task_self(), (uintptr_t)binding_addr, section_size, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
      if (err == KERN_SUCCESS) {
        *binding_addr = entry->rebindings[j].replacement;
      }
      return true;
    }
  }
  return false;
}

static bool try_rebind_symbol(const char *symbol_name,
                              void **binding_addr,
                              struct RebindingsEntry *rebindings,
                              size_t section_size) {
  if (!symbol_name || symbol_name[0] == '\0' || symbol_name[1] == '\0') {
    return false;
  }
  struct RebindingsEntry *cur = rebindings;
  while (cur) {
    if (check_and_apply_rebinding(cur, symbol_name, binding_addr, section_size)) {
      return true;
    }
    cur = cur->next;
  }
  return false;
}

static void perform_rebinding_with_section(struct RebindingsEntry *rebindings,
                                           section_t *section,
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab) {
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);

  for (uint i = 0; i < section->size / sizeof(void *); i++) {
    uint32_t symtab_index = indirect_symbol_indices[i];
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
      continue;
    }
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
    try_rebind_symbol(symbol_name, &indirect_symbol_bindings[i], rebindings, section->size);
  }
}

static void parse_segment_command(segment_command_t *seg_cmd,
                                  segment_command_t **linkedit,
                                  struct symtab_command **symtab,
                                  struct dysymtab_command **dysymtab) {
  if (seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
    if (strcmp(seg_cmd->segname, SEG_LINKEDIT) == 0) {
      *linkedit = seg_cmd;
    }
  } else if (seg_cmd->cmd == LC_SYMTAB) {
    *symtab = (struct symtab_command*)seg_cmd;
  } else if (seg_cmd->cmd == LC_DYSYMTAB) {
    *dysymtab = (struct dysymtab_command*)seg_cmd;
  }
}

static bool find_linkedit_and_symtabs(const mach_header_t *header,
                                      segment_command_t **linkedit_segment,
                                      struct symtab_command **symtab_cmd,
                                      struct dysymtab_command **dysymtab_cmd) {
  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++) {
    segment_command_t *cur_seg_cmd = (segment_command_t *)cur;
    parse_segment_command(cur_seg_cmd, linkedit_segment, symtab_cmd, dysymtab_cmd);
    cur += cur_seg_cmd->cmdsize;
  }
  return (*symtab_cmd && *dysymtab_cmd && *linkedit_segment && (*dysymtab_cmd)->nindirectsyms > 0);
}

static void rebind_sections_in_segment(segment_command_t *seg_cmd,
                                       uintptr_t segment_addr,
                                       struct RebindingsEntry *rebindings,
                                       intptr_t slide,
                                       nlist_t *symtab,
                                       char *strtab,
                                       uint32_t *indirect_symtab) {
  for (uint j = 0; j < seg_cmd->nsects; j++) {
    section_t *sect = (section_t *)(segment_addr + sizeof(segment_command_t)) + j;
    uint32_t sect_type = sect->flags & SECTION_TYPE;
    if (sect_type == S_LAZY_SYMBOL_POINTERS || sect_type == S_NON_LAZY_SYMBOL_POINTERS) {
      perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
    }
  }
}

static void rebind_data_sections(const mach_header_t *header,
                                 struct RebindingsEntry *rebindings,
                                 intptr_t slide,
                                 nlist_t *symtab,
                                 char *strtab,
                                 uint32_t *indirect_symtab) {
  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++) {
    segment_command_t *cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      bool is_data_seg = (strcmp(cur_seg_cmd->segname, SEG_DATA) == 0);
      bool is_data_const_seg = (strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) == 0);
      if (is_data_seg || is_data_const_seg) {
        rebind_sections_in_segment(cur_seg_cmd, cur, rebindings, slide, symtab, strtab, indirect_symtab);
      }
    }
    cur += cur_seg_cmd->cmdsize;
  }
}

static void rebind_symbols_for_image(struct RebindingsEntry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide) {
  Dl_info info;
  if (dladdr(header, &info) == 0) {
    return;
  }

  segment_command_t *linkedit_segment = NULL;
  struct symtab_command* symtab_cmd = NULL;
  struct dysymtab_command* dysymtab_cmd = NULL;

  if (!find_linkedit_and_symtabs((const mach_header_t *)header, &linkedit_segment, &symtab_cmd, &dysymtab_cmd)) {
    return;
  }

  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
  char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

  rebind_data_sections((const mach_header_t *)header, rebindings, slide, symtab, strtab, indirect_symtab);
}

static void _rebind_symbols_for_image(const struct mach_header *header,
                                      intptr_t slide) {
  rebind_symbols_for_image(_rebindingsHead, header, slide);
}

int rebind_symbols_image(void *header,
                         intptr_t slide,
                         struct Rebinding rebindings[],
                         size_t rebindings_nel) {
  struct RebindingsEntry *rebindings_head = NULL;
  int retval = prepend_rebindings(&rebindings_head, rebindings, rebindings_nel);
  rebind_symbols_for_image(rebindings_head, (const struct mach_header *) header, slide);
  if (rebindings_head) {
    free(rebindings_head->rebindings);
  }
  free(rebindings_head);
  return retval;
}

int rebind_symbols(struct Rebinding rebindings[], size_t rebindings_nel) {
  int retval = prepend_rebindings(&_rebindingsHead, rebindings, rebindings_nel);
  if (retval < 0) {
    return retval;
  }
  if (!_rebindingsHead->next) {
    _dyld_register_func_for_add_image(_rebind_symbols_for_image);
  } else {
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
      _rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
  }
  return retval;
}
