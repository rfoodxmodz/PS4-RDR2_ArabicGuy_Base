#pragma once

#define NULL 0
#define TRUE 1
#define FALSE 0
#define PRIx8     "hhx"
#define PRIx16    "hx"
#define PRIx32    "lx"
#define PRIx64    "llx"
#define PRIu8     "hhu"
#define PRIu16    "hu"
#define PRIu32    "lu"
#define PRIu64    "llu"
typedef unsigned char u8;
typedef unsigned char _BYTE;
typedef unsigned short u16;
typedef unsigned short _WORD;
typedef unsigned int u32;
typedef unsigned long uint32_t;
typedef unsigned long _DWORD;
typedef long long __int64;
typedef unsigned long long u64;
typedef unsigned long long _QWORD;
typedef unsigned long int size_t;
typedef unsigned long uintptr_t;
typedef long intptr_t;


typedef void* Void;
typedef int Any;
typedef unsigned int uint;
typedef int Hash;
typedef int BOOL;
typedef int Entity;
typedef int Player;
typedef int FireId;
typedef int Ped;
typedef int Vehicle;
typedef int Cam;
typedef int CarGenerator;
typedef int Group;
typedef int Train;
typedef int Pickup;
typedef int Object;
typedef int Weapon;
typedef int Interior;
typedef int Blip;
typedef int Texture;
typedef int TextureDict;
typedef int CoverPoint;
typedef int Camera;
typedef int TaskSequence;
typedef int ColourIndex;
typedef int Sphere;
typedef int ScrHandle;

struct Vect3
{
	float x;
	float unk1001;
	float y;
	float unk1002;
	float z;
	float c;
	float d;
	float e;
	float f;
};


typedef struct {
	float x, y;
} Vector2;

typedef struct {
	float x, _padX, y, _padY, z, _padZ;
} Vector3;

typedef struct {
	float x, y, z, w;
} Vector4;

typedef struct {
	int r, g, b, a;
} Color;

typedef	u32	__blksize_t;	/* file block size */
typedef	__int64	__blkcnt_t;	/* file block count */
typedef	int	__clockid_t;	/* clock_gettime()... */
typedef	u64	__cap_rights_t;	/* capability rights */
typedef	u32	__fflags_t;	/* file flags */
typedef	u64	__fsblkcnt_t;
typedef	u64	__fsfilcnt_t;
typedef	u32	__gid_t;
typedef	__int64	__id_t;		/* can hold a gid_t, pid_t, or uid_t */
typedef	u32	__ino_t;	/* inode number */
typedef	__ino_t		ino_t;		/* inode number */
typedef	long		__key_t;	/* IPC key (for Sys V IPC) */
typedef	int	__lwpid_t;	/* Thread ID (a.k.a. LWP) */
typedef	u16	__mode_t;	/* permissions */
typedef	int		__accmode_t;	/* access permissions */
typedef	int		__nl_item;
typedef	u16	__nlink_t;	/* link count */
typedef	__int64	__off_t;	/* file offset */
typedef	int	__pid_t;	/* process [group] */
typedef	__int64	__rlim_t;	/* resource limit - intentionally */
typedef	u8	__sa_family_t;
typedef	u32	__socklen_t;
typedef	__int64	__time_t;		/* time()... */
typedef	__time_t	time_t;
typedef	long		__suseconds_t;	/* microseconds (signed) */
typedef	struct __timer	*__timer_t;	/* timer_gettime()... */
typedef	struct __mq	*__mqd_t;	/* mq_open()... */
typedef	u32	__uid_t;
typedef	unsigned int	__useconds_t;	/* microseconds (unsigned) */
typedef	int		__cpuwhich_t;	/* which parameter for cpuset. */
typedef	int		__cpulevel_t;	/* level parameter for cpuset. */
typedef int		__cpusetid_t;	/* cpuset identifier. */
typedef	int		__ct_rune_t;	/* arg type for ctype funcs */
typedef	__ct_rune_t	__rune_t;	/* rune_t (see above) */
typedef	__ct_rune_t	__wint_t;	/* wint_t (see above) */
typedef	u32	__dev_t;	/* device number */
typedef	u32	__fixpt_t;	/* fixed point number */
typedef	__mode_t	mode_t;		/* permissions */
typedef	__nlink_t	nlink_t;	/* link count */
typedef	__uid_t		uid_t;		/* user id */
typedef	__gid_t		gid_t;		/* group id */
typedef	__off_t	off_t;
typedef	__blkcnt_t	blkcnt_t;
typedef	__blksize_t	blksize_t;
typedef	__fflags_t	fflags_t;	/* file flags */
/*
 * mbstate_t is an opaque object to keep conversion state during multibyte
 * stream conversions.
 */
typedef union {
	char		__mbstate8[128];
	__int64	_mbstateL;	/* for alignment */
} __mbstate_t;
struct timespec {
	time_t	tv_sec;		/* seconds */
	long	tv_nsec;	/* and nanoseconds */
};
struct stat {
	__dev_t   st_dev;		/* inode's device */
	ino_t	  st_ino;		/* inode's number */
	mode_t	  st_mode;		/* inode protection mode */
	nlink_t	  st_nlink;		/* number of hard links */
	uid_t	  st_uid;		/* user ID of the file's owner */
	gid_t	  st_gid;		/* group ID of the file's group */
	__dev_t   st_rdev;		/* device type */
	struct	timespec st_atim;	/* time of last access */
	struct	timespec st_mtim;	/* time of last data modification */
	struct	timespec st_ctim;	/* time of last file status change */
	off_t	  st_size;		/* file size, in bytes */
	blkcnt_t st_blocks;		/* blocks allocated for file */
	blksize_t st_blksize;		/* optimal blocksize for I/O */
	fflags_t  st_flags;		/* user defined flags for file */
	u32 st_gen;		/* file generation number */
	int st_lspare;
	struct timespec st_birthtim;	/* time of file creation */
	/*
	 * Explicitly pad st_birthtim to 16 bytes so that the size of
	 * struct stat is backwards compatible.  We use bitfields instead
	 * of an array of chars so that this doesn't require a C99 compiler
	 * to compile if the size of the padding is 0.  We use 2 bitfields
	 * to cover up to 64 bits on 32-bit machines.  We assume that
	 * CHAR_BIT is 8...
	 */
	unsigned int :(8 / 2) * (16 - (int)sizeof(struct timespec));
	unsigned int :(8 / 2) * (16 - (int)sizeof(struct timespec));
};
