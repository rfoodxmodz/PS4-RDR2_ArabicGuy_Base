#include "kern.h"

#define X86_CR0_WP (1 << 16)
#define VM_PROT_READ 0x01/* read permission */
#define VM_PROT_WRITE 0x02/* write permission */
#define VM_PROT_EXECUTE 0x04/* execute permission */
#define VM_PROT_DEFAULT (VM_PROT_READ | VM_PROT_WRITE)
#define VM_PROT_ALL (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)
typedef int32_t DWORD;
#define LODWORD(_qw)    ((DWORD)(_qw))
#define HIDWORD(_qw)    ((DWORD)(((_qw) >> 32) & 0xffffffff))
void setHIDWORD(uint64_t *_var, DWORD _v)
{
    *_var &= 0xFFFFFFFF;
    *_var |= (uint64_t)_v << 32;
}

static inline __attribute__((always_inline)) uint64_t __readmsr(unsigned long __register) {
  unsigned long __edx;
  unsigned long __eax;
  __asm__("rdmsr"
          : "=d"(__edx), "=a"(__eax)
          : "c"(__register));
  return (((uint64_t)__edx) << 32) | (uint64_t)__eax;
}

static inline __attribute__((always_inline)) uint64_t readCr0(void) {
  uint64_t cr0;
  __asm__ volatile("movq %0, %%cr0"
                   : "=r"(cr0)
                   :
                   : "memory");
  return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0) {
  __asm__ volatile("movq %%cr0, %0"
                   :
                   : "r"(cr0)
                   : "memory");
}

int kpayload_get_fw_version(struct thread *td, struct kpayload_get_fw_version_args *args) {
  void *kernel_base = 0;
  int (*copyout)(const void *kaddr, void *uaddr, size_t len) = 0;

  uint64_t fw_version = 0x666;

  if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K700_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K700_XFAST_SYSCALL];
	if (!memcmp((char *)(kernel_base + K900_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x900; // 9.00
      copyout = (void *)(kernel_base + K900_COPYOUT);
    }
     else if (!memcmp((char *)(kernel_base + K755_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x755; // 7.55
      copyout = (void *)(kernel_base + K755_COPYOUT);
    }
      else if (!memcmp((char *)(kernel_base + K700_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x700; // 7.00, 7.01, 7.02
      copyout = (void *)(kernel_base + K700_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K670_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x670; // 6.70, 6.71, and 6.72
      copyout = (void *)(kernel_base + K670_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K650_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x650; // 6.50 and 6.51
      copyout = (void *)(kernel_base + K650_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K620_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x620; // 6.20
      copyout = (void *)(kernel_base + K620_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K600_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x600; // 6.00 and 6.02
      copyout = (void *)(kernel_base + K600_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K555_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x555; // 5.55 and 5.56
      copyout = (void *)(kernel_base + K555_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K553_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x553; // 5.53
      copyout = (void *)(kernel_base + K553_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K550_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x550; // 5.50
      copyout = (void *)(kernel_base + K550_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K505_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x505; // 5.05 and 5.07
      copyout = (void *)(kernel_base + K505_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K503_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x503; // 5.03
      copyout = (void *)(kernel_base + K503_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K500_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x500; // 5.00 and 5.01
      copyout = (void *)(kernel_base + K500_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K470_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K470_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K470_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x470; // 4.70
      copyout = (void *)(kernel_base + K470_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K471_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K471_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K471_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x471; // 4.71, 4.72, 4.73, and 4.74
      copyout = (void *)(kernel_base + K471_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K450_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K450_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K450_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x450; // 4.50 and 4.55
      copyout = (void *)(kernel_base + K450_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K406_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K406_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K406_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      // TODO: 4.06 and 4.07 overlap here even though other offsets to not
      fw_version = 0x406; // 4.06 and 4.07
      copyout = (void *)(kernel_base + K406_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K405_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K405_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K405_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x405; // 4.05
      copyout = (void *)(kernel_base + K405_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K400_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K400_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K400_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x400; // 4.00 and 4.01
      copyout = (void *)(kernel_base + K400_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K370_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K370_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K370_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x370; // 3.70
      copyout = (void *)(kernel_base + K370_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K355_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K355_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K355_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x355; // 3.55
      copyout = (void *)(kernel_base + K355_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K350_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K350_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K350_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x350; // 3.50
      copyout = (void *)(kernel_base + K350_COPYOUT);
    }
  } else {
    return -1;
  }

  uint64_t uaddr = args->kpayload_get_fw_version_info->uaddr;
  copyout(&fw_version, (uint64_t *)uaddr, 8);

  return 0;
}
void setSrtTime(uint8_t * kernBase, uint64_t time) {
	// uint64_t srtTimePointer = kernBase + 0x26816E0;
	// *(uint64_t*)(v9 + 56) = v43;
    // sub_FFFFFFFFA1B954C0(v49);
    // *(uint64_t*)(v9 + 128) = a1 - v49[0];
    // *(uint32_t*)(v9 + 120) = 1;
	
}
int kpayload_jailbreak(struct thread *td, struct kpayload_jailbreak_args *args) {
  struct filedesc *fd;
  struct ucred *cred;
  fd = td->td_proc->p_fd;
  cred = td->td_proc->p_ucred;

  void *kernel_base;
  uint8_t *ptrKernel;
  void **got_prison0;
  void **got_rootvnode;


  uint64_t fw_version = args->kpayload_jailbreak_info->fw_version;

    if (fw_version == 0x505) {
    // 5.05 and 5.07
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K505_XFAST_SYSCALL];
    ptrKernel = (uint8_t *)kernel_base;
    got_prison0 = (void **)&ptrKernel[K505_PRISON_0];
    got_rootvnode = (void **)&ptrKernel[K505_ROOTVNODE];
    
	 //memory_aslr_patch = &ptrKernel[K505_PROCESS_ASLR];
    //memcpy_patch = &ptrKernel[K505_PATCH_MEMCPY];
    //ptrace_patch = &ptrKernel[K505_PTRACE_CHECK];
    //ptrace_patch_2 = &ptrKernel[K702_PTRACE_CHECK_2];
    //vmap_patch = &ptrKernel[K505_PATCH_VM_MAP];
  } else if (fw_version == 0x550) {
    // 5.50
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K550_XFAST_SYSCALL];
    ptrKernel = (uint8_t *)kernel_base;
    got_prison0 = (void **)&ptrKernel[K550_PRISON_0];
    got_rootvnode = (void **)&ptrKernel[K550_ROOTVNODE];
    
	 //memory_aslr_patch = &ptrKernel[K702_PROCESS_ASLR];
    //memcpy_patch = &ptrKernel[K702_PATCH_MEMCPY];
    //ptrace_patch = &ptrKernel[K702_PTRACE_CHECK];
    //ptrace_patch_2 = &ptrKernel[K702_PTRACE_CHECK_2];
    //vmap_patch = &ptrKernel[K550_PATCH_VM_MAP];
  } else if (fw_version == 0x553) {
    // 5.53
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K553_XFAST_SYSCALL];
    ptrKernel = (uint8_t *)kernel_base;
    got_prison0 = (void **)&ptrKernel[K553_PRISON_0];
    got_rootvnode = (void **)&ptrKernel[K553_ROOTVNODE];
    
	 //memory_aslr_patch = &ptrKernel[K702_PROCESS_ASLR];
    //memcpy_patch = &ptrKernel[K702_PATCH_MEMCPY];
    //ptrace_patch = &ptrKernel[K702_PTRACE_CHECK];
    //ptrace_patch_2 = &ptrKernel[K702_PTRACE_CHECK_2];
    //vmap_patch = &ptrKernel[K553_PATCH_VM_MAP];
  } else if (fw_version == 0x555) {
    // 5.55 and 5.56
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K555_XFAST_SYSCALL];
    ptrKernel = (uint8_t *)kernel_base;
    got_prison0 = (void **)&ptrKernel[K555_PRISON_0];
    got_rootvnode = (void **)&ptrKernel[K555_ROOTVNODE];
    
	 //memory_aslr_patch = &ptrKernel[K702_PROCESS_ASLR];
    //memcpy_patch = &ptrKernel[K702_PATCH_MEMCPY];
    //ptrace_patch = &ptrKernel[K702_PTRACE_CHECK];
    //ptrace_patch_2 = &ptrKernel[K702_PTRACE_CHECK_2];
    //vmap_patch = &ptrKernel[K555_PATCH_VM_MAP];
  } else if (fw_version == 0x600) {
    // 6.00 and 6.02
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K600_XFAST_SYSCALL];
    ptrKernel = (uint8_t *)kernel_base;
    got_prison0 = (void **)&ptrKernel[K600_PRISON_0];
    got_rootvnode = (void **)&ptrKernel[K600_ROOTVNODE];
    
	 //memory_aslr_patch = &ptrKernel[K702_PROCESS_ASLR];
    //memcpy_patch = &ptrKernel[K702_PATCH_MEMCPY];
    //ptrace_patch = &ptrKernel[K702_PTRACE_CHECK];
    //ptrace_patch_2 = &ptrKernel[K702_PTRACE_CHECK_2];
    //vmap_patch = &ptrKernel[K600_PATCH_VM_MAP];
  } else if (fw_version == 0x620) {
    // 6.20
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K620_XFAST_SYSCALL];
    ptrKernel = (uint8_t *)kernel_base;
    got_prison0 = (void **)&ptrKernel[K620_PRISON_0];
    got_rootvnode = (void **)&ptrKernel[K620_ROOTVNODE];
    
	 //memory_aslr_patch = &ptrKernel[K702_PROCESS_ASLR];
    //memcpy_patch = &ptrKernel[K702_PATCH_MEMCPY];
    //ptrace_patch = &ptrKernel[K702_PTRACE_CHECK];
    //ptrace_patch_2 = &ptrKernel[K702_PTRACE_CHECK_2];
    //vmap_patch = &ptrKernel[K620_PATCH_VM_MAP];
  } else if (fw_version == 0x650) {
    // 6.50 and 6.51
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K650_XFAST_SYSCALL];
    ptrKernel = (uint8_t *)kernel_base;
    got_prison0 = (void **)&ptrKernel[K650_PRISON_0];
    got_rootvnode = (void **)&ptrKernel[K650_ROOTVNODE];
    
	 //memory_aslr_patch = &ptrKernel[K702_PROCESS_ASLR];
    //memcpy_patch = &ptrKernel[K702_PATCH_MEMCPY];
    //ptrace_patch = &ptrKernel[K702_PTRACE_CHECK];
    //ptrace_patch_2 = &ptrKernel[K702_PTRACE_CHECK_2];
    //vmap_patch = &ptrKernel[K650_PATCH_VM_MAP];
  } else if (fw_version == 0x670) {
    // 6.70, 6.71, and 6.72
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K670_XFAST_SYSCALL];
    ptrKernel = (uint8_t *)kernel_base;
    got_prison0 = (void **)&ptrKernel[K670_PRISON_0];
    got_rootvnode = (void **)&ptrKernel[K670_ROOTVNODE];
    //memory_aslr_patch = &ptrKernel[K702_PROCESS_ASLR];
    //memcpy_patch = &ptrKernel[K702_PATCH_MEMCPY];
    //ptrace_patch = &ptrKernel[K702_PTRACE_CHECK];
    //ptrace_patch_2 = &ptrKernel[K702_PTRACE_CHECK_2];
    //vmap_patch = &ptrKernel[K670_PATCH_VM_MAP];
  } else if (fw_version == 0x700) {
    // 7.00, 7.01, 7.02
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K700_XFAST_SYSCALL];
    ptrKernel = (uint8_t *)kernel_base;
    got_prison0 = (void **)&ptrKernel[K700_PRISON_0];
    got_rootvnode = (void **)&ptrKernel[K700_ROOTVNODE];

	//memory_aslr_patch = &ptrKernel[K702_PROCESS_ASLR];
    //memcpy_patch = &ptrKernel[K702_PATCH_MEMCPY];
    //ptrace_patch = &ptrKernel[K702_PTRACE_CHECK];
    //ptrace_patch_2 = &ptrKernel[K702_PTRACE_CHECK_2];
    //vmap_patch = &ptrKernel[K700_PATCH_VM_MAP];
	
  } else if (fw_version == 0x755) {
    // 7.00, 7.01, 7.02
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K700_XFAST_SYSCALL];
    ptrKernel = (uint8_t *)kernel_base;
    got_prison0 = (void **)&ptrKernel[K755_PRISON_0];
    got_rootvnode = (void **)&ptrKernel[K755_ROOTVNODE];

	//memory_aslr_patch = &ptrKernel[K755_PROCESS_ASLR];
    //memcpy_patch = &ptrKernel[K755_PATCH_MEMCPY];
    //ptrace_patch = &ptrKernel[K755_PTRACE_CHECK];
    //ptrace_patch_2 = &ptrKernel[K702_PTRACE_CHECK_2];
    //vmap_patch = &ptrKernel[K755_PATCH_VM_MAP];
	
  }
    else if (fw_version == 0x900) {
    // 7.00, 7.01, 7.02
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K900_XFAST_SYSCALL];
    ptrKernel = (uint8_t *)kernel_base;
    got_prison0 = (void **)&ptrKernel[K900_PRISON_0];
    got_rootvnode = (void **)&ptrKernel[K900_ROOTVNODE];
	
  }	else {
    return -1;
  }

  cred->cr_uid = 0;
  cred->cr_ruid = 0;
  cred->cr_rgid = 0;
  cred->cr_groups[0] = 0;

  cred->cr_prison = *got_prison0;
  fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

  void *td_ucred = *(void **)(((char *)td) + 304);

  uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
  *sonyCred = 0xffffffffffffffff;

  uint64_t *sceProcessAuthorityId = (uint64_t *)(((char *)td_ucred) + 88);
  *sceProcessAuthorityId = 0x3801000000000013;

  uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
  *sceProcCap = 0xffffffffffffffff;

  uint64_t cr0 = readCr0();
  writeCr0(cr0 & ~X86_CR0_WP);

 if (fw_version == 0x505) {
    // 5.05 and 5.07
//patch memcpy first 5.05
	*(uint8_t *)(ptrKernel + 0x001EA53D) = 0xEB;


    // patch sceSblACMgrIsAllowedSystemLevelDebugging 5.05
    memcpy((void *)(ptrKernel + 0x00011730), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrHasMmapSelfCapability 5.05
    memcpy((void *)(ptrKernel + 0x000117B0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);


     // patch sceSblACMgrIsAllowedToMmapSelf 5.05
    memcpy((void *)(ptrKernel + 0x000117C0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);


    // disable sysdump_perform_dump_on_fatal_trap 5.05
    // will continue execution and give more information on crash, such as rip
    *(uint8_t *)(ptrKernel + 0x007673E0) = 0xC3;


    // self patches 5.05
    memcpy((void *)(ptrKernel + 0x0013F03F), "\x31\xC0\x90\x90\x90", 5);


    // patch vm_map_protect check 5.05
    memcpy((void *)(ptrKernel + 0x001A3C08), "\x90\x90\x90\x90\x90\x90", 6);

  
    // patch ptrace
    *(uint8_t *)(ptrKernel + 0x30D9AA) = 0xEB;
    memcpy((void *)(ptrKernel + 0x30DE01), "\xE9\xD0\x00\x00\x00", 5);

	// patch ASLR
    *(uint16_t *)(ptrKernel + 0x194875) = 0x9090;

 // patch kmem_alloc 5.05
    *(uint8_t *)(ptrKernel + 0x000FCD48) = VM_PROT_ALL;
    *(uint8_t *)(ptrKernel + 0x000FCD56) = VM_PROT_ALL;

  } else if (fw_version == 0x550) {
    // 5.50
   
  } else if (fw_version == 0x553) {
    // 5.53
   
  } else if (fw_version == 0x555) {
    // 5.55 and 5.56
   
  } else if (fw_version == 0x600) {
    // 6.00 and 6.02
   
  } else if (fw_version == 0x620) {
    // 6.20
   
  } else if (fw_version == 0x650) {
    // 6.50 and 6.51
   
  } else if (fw_version == 0x670) {
    // 6.70, 6.71, and 6.72
	// patch memcpy first
	*(uint8_t *)(ptrKernel + 0x003C15BD) = 0xEB;

    // patch ptrace
    *(uint8_t *)(ptrKernel + 0x10F879) = 0xEB;
	memcpy((void *)(ptrKernel + 0x10FD22), "\xE9\xE2\x02\x00\x00", 5);

    // Disable process aslr
    *(uint8_t *)(ptrKernel + 0x3CECE1) = 0xEB;
	
  } else if (fw_version == 0x700) {
  //patch memcpy first 9.00

    // 7.00, 7.01, 7.02
    // patch memcpy first
    *(uint8_t *)(ptrKernel + 0x0002F04D) = 0xEB;

    // patch sceSblACMgrIsAllowedSystemLevelDebugging
    memcpy((void *)(ptrKernel + 0x1CB880), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrHasMmapSelfCapability
    memcpy((void *)(ptrKernel + 0x1CB8F0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrIsAllowedToMmapSelf
    memcpy((void *)(ptrKernel + 0x1CB910), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // disable sysdump_perform_dump_on_fatal_trap
    // will continue execution and give more information on crash, such as rip
    *(uint8_t *)(ptrKernel + 0x7889E0) = 0xC3;
	
	
    // self patches
    memcpy((void *)(ptrKernel + 0x1D40BB), "\x31\xC0\x90\x90\x90", 5);

    // patch ptrace
    *(uint8_t *)(ptrKernel + 0x448D5) = 0xEB;
    // remove all these bullshit checks from ptrace, by golden
    memcpy((void *)(ptrKernel + 0x44DAF), "\xE9\x7C\x02\x00\x00", 5);

    // patch ASLR, thanks 2much4u
    *(uint8_t *)(ptrKernel + 0xC1F9A) = 0xEB;

    // patch kmem_alloc
    *(uint8_t *)(ptrKernel + 0x1171BE) = VM_PROT_ALL;
    *(uint8_t *)(ptrKernel + 0x1171C6) = VM_PROT_ALL;
	
  } else if (fw_version == 0x755) {
    // 7.55
    // patch memcpy first
    *(uint8_t *)(ptrKernel + 0x28F80D) = 0xEB;

    // patch sceSblACMgrIsAllowedSystemLevelDebugging
    memcpy((void *)(ptrKernel + 0x364CD0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrHasMmapSelfCapability
    memcpy((void *)(ptrKernel + 0x364D40), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrIsAllowedToMmapSelf
    memcpy((void *)(ptrKernel + 0x364D60), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // disable sysdump_perform_dump_on_fatal_trap
    // will continue execution and give more information on crash, such as rip
    *(uint8_t *)(ptrKernel + 0x0077F9A0) = 0xC3;

    // self patches
    memcpy((void *)(ptrKernel + 0x0DCED1), "\x31\xC0\x90\x90\x90", 5);

    // patch vm_map_protect check
   // memcpy((void *)(ptrKernel + 0x003014C8), "\x90\x90\x90\x90\x90\x90", 6);

    // patch ptrace
    *(uint8_t *)(ptrKernel + 0x361CF5) = 0xEB;
    memcpy((void *)(ptrKernel + 0x3621CF), "\xE9\x7C\x02\x00\x00", 5);

    // patch ASLR, thanks 2much4u
    *(uint8_t *)(ptrKernel + 0x218AF4) = 0xEB;

    // patch kmem_alloc
    *(uint8_t *)(ptrKernel + 0x1754AC) = VM_PROT_ALL;
    *(uint8_t *)(ptrKernel + 0x1754B4) = VM_PROT_ALL;

  }
   else if (fw_version == 0x900) {
   //patch memcpy first 9.00
	*(uint8_t *)(ptrKernel + 0x2713FD) = 0xEB;//9
	
    // patch sceSblACMgrIsAllowedSystemLevelDebugging
    memcpy((void *)(ptrKernel + 0x8BC20), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrHasMmapSelfCapability
    memcpy((void *)(ptrKernel + 0x8BC90), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrIsAllowedToMmapSelf
    memcpy((void *)(ptrKernel + 0x8BCB0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // disable sysdump_perform_dump_on_fatal_trap
    // will continue execution and give more information on crash, such as rip
    *(uint8_t *)(ptrKernel + 0x00767E30) = 0xC3;

    // self patches
    memcpy((void *)(ptrKernel + 0x168051), "\x31\xC0\x90\x90\x90", 5);

    // patch ptrace
	ptrKernel[K900_PTRACE_CHECK] = 0xEB;//9
    memcpy((void *)(ptrKernel + 0x41F9D1), "\xE9\x7C\x02\x00\x00", 5);//9
	
	
    // Disable process aslr
	*(uint16_t*)&ptrKernel[K900_PROCESS_ASLR] = 0x9090;//9
    
    // patch kmem_alloc
    *(uint8_t *)(ptrKernel + 0x37BF3C) = VM_PROT_ALL;
    *(uint8_t *)(ptrKernel + 0x37BF44) = VM_PROT_ALL;

  } else {
    return -1;
  }

  writeCr0(cr0);

  return 0;
}

uint64_t get_fw_version(void) {
  uint64_t fw_version = 0x666;
  uint64_t *fw_version_ptr = mmap(NULL, 8, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  struct kpayload_get_fw_version_info kpayload_get_fw_version_info;
  kpayload_get_fw_version_info.uaddr = (uint64_t)fw_version_ptr;
  kexec(&kpayload_get_fw_version, &kpayload_get_fw_version_info);
  memcpy(&fw_version, fw_version_ptr, 8);
  munmap(fw_version_ptr, 8);

  return fw_version;
}


int jailbreak(uint64_t fw_version) {
  struct kpayload_jailbreak_info kpayload_jailbreak_info;
  kpayload_jailbreak_info.fw_version = fw_version;
  kexec(&kpayload_jailbreak, &kpayload_jailbreak_info);

  return 0;
}