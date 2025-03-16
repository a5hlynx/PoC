# References
# https://github.com/isciurus/sleuthkit
# https://web.git.kernel.org/pub/scm/fs/xfs/xfsprogs-dev.git

from ctypes import *
from enum import IntEnum, Enum
import sys
import datetime

XFSLABEL_MAX = 12

if sys.maxsize > 2**32:
	SIZEOF_LONG = 8
else:
	SIZEOF_LONG = 4

S_IFMT = 0o0170000
S_IFIFO = 0o0010000
S_IFCHR = 0o0020000
S_IFDIR = 0o0040000
S_IFBLK = 0o0060000
S_IFREG = 0o0100000
S_IFLNK = 0o0120000
S_IFSOCK = 0o0140000
S_ISVTX = 0o0001000

XFS_AGI_UNLINKED_BUCKETS = 64
XFS_MD_MAGIC = 0x5846534d
XFS_SB_MAGIC = 0x58465342
XFS_AGI_MAGIC = 0x58414749
XFS_AGF_MAGIC = 0x58414746
XFS_AGFL_MAGIC = 0x5841464c
XFS_AGF_VERSION = 1
XFS_AGI_VERSION = 1
XFS_IBT_MAGIC = 0x49414254
XFS_IBT_CRC_MAGIC = 0x49414233
XFS_FIBT_MAGIC = 0x46494254
XFS_FIBT_CRC_MAGIC = 0x46494233
XFS_DINODE_MAGIC = 0x494e
XFS_DQUOT_MAGIC = 0x4451

XFS_ABTC_MAGIC = 0x41425443
XFS_ABTB_MAGIC = 0x41425442
XFS_ABTB_CRC_MAGIC = 0x41423342
XFS_ABTC_CRC_MAGIC = 0x41423343

XFS_DIFLAG2_REFLINK_BIT = 1
XFS_DIFLAG2_COWEXTSIZE_BIT = 2
XFS_DIFLAG2_BIGTIME_BIT = 3
XFS_DIFLAG2_NREXT64_BIT = 4

XFS_DIFLAG2_REFLINK = (1 << XFS_DIFLAG2_REFLINK_BIT)
XFS_DIFLAG2_COWEXTSIZE = (1 << XFS_DIFLAG2_COWEXTSIZE_BIT)
XFS_DIFLAG2_BIGTIME = (1 << XFS_DIFLAG2_BIGTIME_BIT)
XFS_DIFLAG2_NREXT64 = (1 << XFS_DIFLAG2_NREXT64_BIT)

XFS_SB_FEAT_COMPAT_ALL = 0
XFS_SB_FEAT_COMPAT_UNKNOWN = ~XFS_SB_FEAT_COMPAT_ALL
XFS_SB_FEAT_RO_COMPAT_FINOBT = (1 << 0)
XFS_SB_FEAT_RO_COMPAT_RMAPBT = (1 << 1)
XFS_SB_FEAT_RO_COMPAT_REFLINK = (1 << 2)
XFS_SB_FEAT_RO_COMPAT_INOBTCNT = (1 << 3)
XFS_SB_FEAT_RO_COMPAT_ALL = (XFS_SB_FEAT_RO_COMPAT_FINOBT | XFS_SB_FEAT_RO_COMPAT_RMAPBT | \
								XFS_SB_FEAT_RO_COMPAT_REFLINK| XFS_SB_FEAT_RO_COMPAT_INOBTCNT)
XFS_SB_FEAT_RO_COMPAT_UNKNOWN = ~XFS_SB_FEAT_RO_COMPAT_ALL
XFS_SB_FEAT_INCOMPAT_FTYPE = (1 << 0)
XFS_SB_FEAT_INCOMPAT_SPINODES = (1 << 1)
XFS_SB_FEAT_INCOMPAT_META_UUID = (1 << 2)
XFS_SB_FEAT_INCOMPAT_BIGTIME = (1 << 3)
XFS_SB_FEAT_INCOMPAT_NEEDSREPAIR = (1 << 4)
XFS_SB_FEAT_INCOMPAT_NREXT64 = (1 << 5)
XFS_SB_FEAT_INCOMPAT_ALL = (XFS_SB_FEAT_INCOMPAT_FTYPE | XFS_SB_FEAT_INCOMPAT_SPINODES| \
							XFS_SB_FEAT_INCOMPAT_META_UUID| XFS_SB_FEAT_INCOMPAT_BIGTIME| \
							XFS_SB_FEAT_INCOMPAT_NEEDSREPAIR| XFS_SB_FEAT_INCOMPAT_NREXT64)
XFS_SB_FEAT_INCOMPAT_UNKNOWN = ~XFS_SB_FEAT_INCOMPAT_ALL
XFS_SB_FEAT_INCOMPAT_LOG_XATTRS = (1 << 0)
XFS_SB_FEAT_INCOMPAT_LOG_ALL = (XFS_SB_FEAT_INCOMPAT_LOG_XATTRS)
XFS_SB_FEAT_INCOMPAT_LOG_UNKNOWN = ~XFS_SB_FEAT_INCOMPAT_LOG_ALL

XFS_FEAT_ATTR = (0x0000000000000001 << 0)
XFS_FEAT_NLINK = (0x0000000000000001 << 1)
XFS_FEAT_QUOTA = (0x0000000000000001 << 2)
XFS_FEAT_ALIGN = (0x0000000000000001 << 3)
XFS_FEAT_DALIGN = (0x0000000000000001 << 4)
XFS_FEAT_LOGV2 = (0x0000000000000001 << 5)
XFS_FEAT_SECTOR = (0x0000000000000001 << 6)
XFS_FEAT_EXTFLG = (0x0000000000000001 << 7)
XFS_FEAT_ASCIICI = (0x0000000000000001 << 8)
XFS_FEAT_LAZYSBCOUNT = (0x0000000000000001 << 9)
XFS_FEAT_ATTR2 = (0x0000000000000001 << 10)
XFS_FEAT_PARENT = (0x0000000000000001 << 11)
XFS_FEAT_PROJID32 = (0x0000000000000001 << 12)
XFS_FEAT_CRC = (0x0000000000000001 << 13)
XFS_FEAT_V3INODES = (0x0000000000000001 << 14)
XFS_FEAT_PQUOTINO = (0x0000000000000001 << 15)
XFS_FEAT_FTYPE = (0x0000000000000001 << 16)
XFS_FEAT_FINOBT = (0x0000000000000001 << 17)
XFS_FEAT_RMAPBT = (0x0000000000000001 << 18)
XFS_FEAT_REFLINK = (0x0000000000000001 << 19)
XFS_FEAT_SPINODES = (0x0000000000000001 << 20)
XFS_FEAT_META_UUID = (0x0000000000000001 << 21)
XFS_FEAT_REALTIME = (0x0000000000000001 << 22)
XFS_FEAT_INOBTCNT = (0x0000000000000001 << 23)
XFS_FEAT_BIGTIME = (0x0000000000000001 << 24)
XFS_FEAT_NEEDSREPAIR = (0x0000000000000001 << 25)
XFS_FEAT_NREXT64 = (0x0000000000000001 << 26)

XFS_SB_VERSION_NUMBITS = 0x000f
XFS_SB_VERSION_ALLFBITS = 0xfff0
XFS_SB_VERSION_ATTRBIT = 0x0010
XFS_SB_VERSION_NLINKBIT = 0x0020
XFS_SB_VERSION_QUOTABIT = 0x0040
XFS_SB_VERSION_ALIGNBIT = 0x0080
XFS_SB_VERSION_DALIGNBIT = 0x0100
XFS_SB_VERSION_SHAREDBIT = 0x0200
XFS_SB_VERSION_LOGV2BIT = 0x0400
XFS_SB_VERSION_SECTORBIT = 0x0800
XFS_SB_VERSION_EXTFLGBIT = 0x1000
XFS_SB_VERSION_DIRV2BIT = 0x2000
XFS_SB_VERSION_BORGBIT = 0x4000
XFS_SB_VERSION_MOREBITSBIT = 0x8000

XLOG_MAX_ICLOGS = 8
XLOG_MAX_RECORD_BSHIFT = 18
XLOG_BIG_RECORD_BSHIFT = 15

NSEC_PER_SEC = 1000000000
S32_MIN = -2147483648
XFS_BIGTIME_EPOCH_OFFSET = -S32_MIN

XFS_BUFTARG_INJECT_WRITE_FAIL=(1 << 2)
XFS_MAX_SECTORSIZE_LOG = 15

LIBXFS_ISREADONLY = 0x0002
LIBXFS_ISINACTIVE = 0x0004
LIBXFS_DANGEROUSLY = 0x0008
LIBXFS_EXCLUSIVELY = 0x0010
LIBXFS_DIRECT =  0x0020
CACHE_MISCOMPARE_PURGE = (1<<0)
RADIX_TREE_MAP_SHIFT = 6
RADIX_TREE_INDEX_BITS = (8 * SIZEOF_LONG)
RADIX_TREE_MAX_PATH = (RADIX_TREE_INDEX_BITS//RADIX_TREE_MAP_SHIFT + 2)
CHAR_BIT = 8
RADIX_TREE_MAX_TAGS = 2
BITS_PER_LONG = (SIZEOF_LONG * CHAR_BIT)
RADIX_TREE_MAP_SIZE = 1 << RADIX_TREE_MAP_SHIFT
RADIX_TREE_TAG_LONGS = ((RADIX_TREE_MAP_SIZE + BITS_PER_LONG - 1) // BITS_PER_LONG)

MAXPATHLEN = 4096
PROC_MOUNTED = "/proc/mounts"
_PATH_MOUNTED = "/etc/mtab"
MOUNTED = _PATH_MOUNTED
CHECK_MOUNT_VERBOSE = 0x1
CHECK_MOUNT_WRITABLE = 0x2
MNTOPT_RO = "ro"

XFS_MIN_SECTORSIZE_LOG = 9
XFS_MIN_SECTORSIZE = (1 << XFS_MIN_SECTORSIZE_LOG)
XFS_MAX_SECTORSIZE_LOG = 15
XFS_MAX_SECTORSIZE = (1 << XFS_MAX_SECTORSIZE_LOG)
RAMDISK_MAJOR = 1

_IOC_NONE = 0
_IOC_WRITE =1
_IOC_READ = 2
_IOC_SIZEBITS = 14
_IOC_NRBITS = 8
_IOC_NRSHIFT = 0
_IOC_TYPEBITS = 8
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS

BBSHIFT = 9
BBSIZE = 1 << BBSHIFT

XFS_MAX_BLOCKSIZE_LOG = 16
XFS_MAX_BLOCKSIZE = (1 << XFS_MAX_BLOCKSIZE_LOG)
XFS_BLF_CHUNK = 128
NBBY = 8
NBWORD = NBBY * sizeof(c_uint)
__XFS_BLF_DATAMAP_SIZE = ((XFS_MAX_BLOCKSIZE // XFS_BLF_CHUNK) // NBWORD)
XFS_BLF_DATAMAP_SIZE = (__XFS_BLF_DATAMAP_SIZE + 1)
XFS_DA_NODE_MAXDEPTH = 5

XFS_MAXINUMBER = ((1 << 56) - 1)
XFS_MAXINUMBER_32 = ((1 << 32) - 1)

XFS_SB_VERSION_1 = 1
XFS_SB_VERSION_2 = 2
XFS_SB_VERSION_3 = 3
XFS_SB_VERSION_4 = 4
XFS_SB_VERSION_5 = 5
XFS_SB_VERSION_NUMBITS =  0x000f
XFS_SB_VERSION_ALLFBITS = 0xfff0
XFS_SB_VERSION_ATTRBIT = 0x0010
XFS_SB_VERSION_NLINKBIT = 0x0020
XFS_SB_VERSION_QUOTABIT = 0x0040
XFS_SB_VERSION_ALIGNBIT = 0x0080
XFS_SB_VERSION_DALIGNBIT = 0x0100
XFS_SB_VERSION_SHAREDBIT = 0x0200
XFS_SB_VERSION_LOGV2BIT = 0x0400
XFS_SB_VERSION_SECTORBIT = 0x0800
XFS_SB_VERSION_EXTFLGBIT = 0x1000
XFS_SB_VERSION_DIRV2BIT = 0x2000 
XFS_SB_VERSION_BORGBIT = 0x4000
XFS_SB_VERSION_MOREBITSBIT = 0x8000

XFS_SB_VERSION2_RESERVED1BIT = 0x00000001
XFS_SB_VERSION2_LAZYSBCOUNTBIT = 0x00000002
XFS_SB_VERSION2_RESERVED4BIT = 0x00000004
XFS_SB_VERSION2_ATTR2BIT = 0x00000008
XFS_SB_VERSION2_PARENTBIT = 0x00000010
XFS_SB_VERSION2_PROJID32BIT = 0x00000080
XFS_SB_VERSION2_CRCBIT = 0x00000100
XFS_SB_VERSION2_FTYPE = 0x00000200

BMBT_EXNTFLAG_BITLEN = 1
BMBT_STARTOFF_BITLEN = 54
BMBT_STARTBLOCK_BITLEN = 52
BMBT_BLOCKCOUNT_BITLEN = 21

XFS_SB_FEAT_INCOMPAT_FTYPE = (1 << 0)
XFS_SB_FEAT_INCOMPAT_META_UUID = (1 << 2)

XFS_DIR2_DATA_ALIGN_LOG = 3
XFS_DIR2_DATA_ALIGN = (1 << XFS_DIR2_DATA_ALIGN_LOG)
XFS_DIR2_SPACE_SIZE = (1 << (32 + XFS_DIR2_DATA_ALIGN_LOG)) & 0xffffffffffffffff
XFS_DIR2_LEAF_SPACE = 1
XFS_DIR2_FREE_SPACE = 2
XFS_DIR2_LEAF_OFFSET = XFS_DIR2_LEAF_SPACE * XFS_DIR2_SPACE_SIZE
XFS_DIR2_FREE_OFFSET = XFS_DIR2_FREE_SPACE * XFS_DIR2_SPACE_SIZE

XFS_DATA_FORK = 0
XFS_ATTR_FORK = 1
XFS_COW_FORK = 2

XFS_DIR2_BLOCK_MAGIC = 0x58443242
XFS_DIR2_DATA_MAGIC = 0x58443244
XFS_DIR2_FREE_MAGIC = 0x58443246

XFS_DIR3_BLOCK_MAGIC = 0x58444233
XFS_DIR3_DATA_MAGIC = 0x58444433
XFS_DIR3_FREE_MAGIC = 0x58444633
XFS_DIR2_DATA_FD_COUNT = 3

XFS_ATTR_LOCAL_BIT = 0
XFS_ATTR_ROOT_BIT = 1
XFS_ATTR_SECURE_BIT = 2
XFS_ATTR_PARENT_BIT = 3
XFS_ATTR_INCOMPLETE_BIT = 7

XFS_ATTR_LOCAL = 0x0001 << XFS_ATTR_LOCAL_BIT
XFS_ATTR_ROOT = 0x0001 << XFS_ATTR_ROOT_BIT
XFS_ATTR_SECURE = 0x0001 << XFS_ATTR_SECURE_BIT
XFS_ATTR_PARENT = 0x0001 << XFS_ATTR_PARENT_BIT
XFS_ATTR_INCOMPLETE = 0x0001 << XFS_ATTR_INCOMPLETE_BIT

LIBXFS_BHASHSIZE_sbp = 1 << 10
CACHE_MAX_PRIORITY = 15
CACHE_DIRTY_PRIORITY = CACHE_MAX_PRIORITY + 1
HASH_CACHE_RATIO = 8
NULLFSINO = -1

XFS_INO32_SIZE = 4
XFS_INO64_SIZE = 8
XFS_INO64_DIFF = (XFS_INO64_SIZE - XFS_INO32_SIZE)
XLOG_HEADER_CYCLE_SIZE = (32*1024)
BBSHIFT = 9
BBSIZE = (1<<BBSHIFT)

XLOG_FMT_UNKNOWN = 0
XLOG_FMT_LINUX_LE = 1
XLOG_FMT_LINUX_BE = 2
XLOG_FMT_IRIX_BE = 3
XLOG_HEADER_MAGIC = 0xfeedbabe

XFS_TRANSACTION = 0x69
XFS_VOLUME = 0x2
XFS_LOG = 0xaa

XLOG_START_TRANS = 0x01
XLOG_COMMIT_TRANS = 0x02
XLOG_CONTINUE_TRANS = 0x04
XLOG_WAS_CONT_TRANS = 0x08
XLOG_END_TRANS = 0x10
XLOG_UNMOUNT_TRANS = 0x20

XLOG_UNMOUNT_TYPE = 0x556e

XFS_TRANS_HEADER_MAGIC = 0x5452414e

XFS_LI_EFI = 0x1236
XFS_LI_EFD = 0x1237
XFS_LI_IUNLINK = 0x1238
XFS_LI_INODE = 0x123b
XFS_LI_BUF = 0x123c
XFS_LI_DQUOT = 0x123d
XFS_LI_QUOTAOFF = 0x123e
XFS_LI_ICREATE = 0x123f
XFS_LI_RUI = 0x1240
XFS_LI_RUD = 0x1241
XFS_LI_CUI = 0x1242
XFS_LI_CUD = 0x1243
XFS_LI_BUI = 0x1244
XFS_LI_BUD = 0x1245
XFS_LI_ATTRI = 0x1246
XFS_LI_ATTRD = 0x1247

XFS_TRANS_SETATTR_NOT_SIZE = 1
XFS_TRANS_SETATTR_SIZE = 2
XFS_TRANS_INACTIVE = 3
XFS_TRANS_CREATE = 4
XFS_TRANS_CREATE_TRUNC = 5
XFS_TRANS_TRUNCATE_FILE = 6
XFS_TRANS_REMOVE = 7
XFS_TRANS_LINK = 8
XFS_TRANS_RENAME = 9
XFS_TRANS_MKDIR = 10
XFS_TRANS_RMDIR = 11
XFS_TRANS_SYMLINK = 12
XFS_TRANS_SET_DMATTRS = 13
XFS_TRANS_GROWFS = 14
XFS_TRANS_STRAT_WRITE = 15
XFS_TRANS_DIOSTRAT = 16
XFS_TRANS_WRITEID = 18
XFS_TRANS_ADDAFORK = 19
XFS_TRANS_ATTRINVAL = 20
XFS_TRANS_ATRUNCATE = 21
XFS_TRANS_ATTR_SET = 22
XFS_TRANS_ATTR_RM = 23
XFS_TRANS_ATTR_FLAG = 24
XFS_TRANS_CLEAR_AGI_BUCKET = 25
XFS_TRANS_SB_CHANGE = 28
XFS_TRANS_QM_QUOTAOFF = 29
XFS_TRANS_QM_DQALLOC = 30
XFS_TRANS_QM_SETQLIM = 31
XFS_TRANS_QM_DQCLUSTER = 32
XFS_TRANS_QM_QINOCREATE = 33
XFS_TRANS_QM_QUOTAOFF_END = 34
XFS_TRANS_FSYNC_TS = 36
XFS_TRANS_GROWFSRT_ALLOC = 37
XFS_TRANS_GROWFSRT_ZERO = 38
XFS_TRANS_GROWFSRT_FREE = 39
XFS_TRANS_SWAPEXT = 40
XFS_TRANS_CHECKPOINT = 42
XFS_TRANS_ICREATE = 43
XFS_TRANS_CREATE_TMPFILE = 44

XFS_ILOG_CORE = 0x001
XFS_ILOG_DDATA = 0x002
XFS_ILOG_DEXT = 0x004
XFS_ILOG_DBROOT = 0x008
XFS_ILOG_DEV = 0x010
XFS_ILOG_UUID = 0x020
XFS_ILOG_ADATA = 0x040
XFS_ILOG_AEXT = 0x080
XFS_ILOG_ABROOT = 0x100
XFS_ILOG_DOWNER = 0x200
XFS_ILOG_AOWNER = 0x400
XFS_ILOG_TIMESTAMP = 0x4000

XFS_ILOG_NONCORE = (XFS_ILOG_DDATA | XFS_ILOG_DEXT | XFS_ILOG_DBROOT | XFS_ILOG_DEV \
					| XFS_ILOG_ADATA | XFS_ILOG_AEXT |XFS_ILOG_ABROOT | XFS_ILOG_DOWNER \
					| XFS_ILOG_AOWNER)
XFS_ILOG_DFORK = (XFS_ILOG_DDATA | XFS_ILOG_DEXT | XFS_ILOG_DBROOT)
XFS_ILOG_AFORK = (XFS_ILOG_ADATA | XFS_ILOG_AEXT | XFS_ILOG_ABROOT)
XFS_ILOG_ALL = (XFS_ILOG_CORE | XFS_ILOG_DDATA | XFS_ILOG_DEXT | XFS_ILOG_DBROOT \
					| XFS_ILOG_DEV | XFS_ILOG_ADATA | XFS_ILOG_AEXT | XFS_ILOG_ABROOT \
					| XFS_ILOG_TIMESTAMP | XFS_ILOG_DOWNER | XFS_ILOG_AOWNER)

XFS_BLF_INODE_BUF = (1<<0)
XFS_BLF_CANCEL = (1<<1)
XFS_BLF_UDQUOT_BUF = (1<<2)
XFS_BLF_PDQUOT_BUF = (1<<3)
XFS_BLF_GDQUOT_BUF = (1<<4)

XFS_BLFT_BITS = 5
XFS_BLFT_SHIFT = 11
XFS_BLFT_MASK = (((1 << XFS_BLFT_BITS) - 1) << XFS_BLFT_SHIFT)

NO_ERROR = 0
BAD_HEADER = -1
PARTIAL_READ = -2
FULL_READ = -3
ZEROED_LOG = -4
CLEARED_BLKS = -5

XLOG_HEADER_CYCLE_SIZE = 32*1024

def _IOC_TYPECHECK(t):
	return sizeof(t)

def _IOC(dir, type, nr, size):
	return (dir << _IOC_DIRSHIFT) | (type << _IOC_TYPESHIFT) | (nr << _IOC_NRSHIFT) | (size << _IOC_SIZESHIFT)

def _IOW(type, nr, size):
	return _IOC(_IOC_WRITE, type, nr, _IOC_TYPECHECK(size))

def _IOR(type, nr, size):
	return _IOC(_IOC_READ, type, nr, _IOC_TYPECHECK(size))

def _IO(type,nr):
	return _IOC(_IOC_NONE, type, nr, 0)

BLKFLSBUF = _IO(0x12, 97)
BLKBSZSET =  _IOW(0x12, 113, c_size_t)
BLKGETSIZE64 = _IOR(0x12, 114, c_size_t)
MAX_DEVS=10

xfs_bmbt_ptr = c_uint64
xfs_bmdr_ptr = c_uint64
xfs_rtblock = c_uint64
xfs_agblock = c_uint32
xfs_agnumber = c_uint32
xfs_lsn = c_int64
xfs_agino = c_uint32
xfs_fsize = c_int64
xfs_ufsize = c_uint64
xfs_suminfo = c_int32
xfs_rtword = c_uint32
xfs_dablk = c_uint32
xfs_dahash = c_uint32
xfs_srtblock = c_int64
xfs_exntst = c_uint32
xfs_ino = c_uint64
xfs_rfsblock = c_uint64
xfs_extlen = c_uint32
xfs_extnum = c_uint32
xfs_aextnum = c_uint16
xfs_bmbt_rec_base = c_uint64
xfs_fsblock = c_uint64
xfs_fileoff = c_uint64
xfs_filblks = c_uint64
xfs_dir2_data_off = c_uint16
xfs_dir2_ino8 = c_uint8 * 8
xfs_dir2_ino4 = c_uint8 * 4
xfs_rgnumber = c_uint32
xfs_rtxlen = c_uint32
xlog_tid = c_uint32

class xfs_exntst_enum(IntEnum):
	XFS_EXT_NORM = 0
	XFS_EXT_UNWRITTEN = 1
	XFS_EXT_INVALID = 2

class xfs_dir3_ft(IntEnum):
	XFS_DIR3_FT_UNKNOWN = 0
	XFS_DIR3_FT_REG_FILE = 1
	XFS_DIR3_FT_DIR = 2
	XFS_DIR3_FT_CHRDEV = 3
	XFS_DIR3_FT_BLKDEV = 4
	XFS_DIR3_FT_FIFO = 5
	XFS_DIR3_FT_SOCK = 6
	XFS_DIR3_FT_SYMLINK = 7
	XFS_DIR3_FT_WHT = 8
	XFS_DIR3_FT_MAX = 9
	XFS_DIR3_FT_ERR = -1
	@classmethod
	def _missing_(cls, value):
		return cls.XFS_DIR3_FT_ERR

class xfs_dinode_fmt(IntEnum):
	XFS_DINODE_FMT_DEV = 0
	XFS_DINODE_FMT_LOCAL = 1
	XFS_DINODE_FMT_EXTENTS = 2
	XFS_DINODE_FMT_BTREE = 3
	XFS_DINODE_FMT_UUID = 4
	XFS_DINODE_FMT_RMAP = 5

class xfs_timestamp(Structure):
	_fields_ = [
		("t_sec", c_int32),
		("t_nsec", c_int32)
	]
xfs_log_timestamp = xfs_timestamp

class uuid(Structure):
	_fields_ = [
		("u_bits", c_ubyte * 16)
	]

class u_uuid(Structure):
	_fields_ = [
		("time_low", c_uint32),
		("time_mid", c_uint16),
		("time_hi_and_version", c_uint16),
		("clock_seq", c_uint16),
		("node", c_uint8 * 6)
	]

class xfs_dir2_inou(Union):
	_fields_ = [
		("i8", xfs_dir2_ino8),
		("i4", xfs_dir2_ino4),
	]

class xfs_btree_ptr(Union):
	_fields_ = [
		("s", c_uint32),
		("l", c_uint64)
	]

class xfs_dir2_sf_hdr(Structure):
	_fields_ = [
		("count", c_uint8),
		("i8count", c_uint8),
		("parent", xfs_dir2_inou)
	]
	def size(self):
		if self.i8count > 0:
			return sizeof(xfs_dir2_sf_hdr)
		else:
			return sizeof(xfs_dir2_sf_hdr) - XFS_INO64_DIFF

class xfs_dir2_sf_off(Structure):
	_fields_ = [
		("i", c_uint8 * 2)
	]

class xfs_dir2_sf_entry(Structure):
	_fields_ = [
		("namelen", c_uint8),
		("offset", xfs_dir2_sf_off),
		("name", c_uint8 * 1),
		("ftype", c_uint8),
		("inumber", xfs_dir2_inou),
	]

class xfs_dir2_sf(Structure):
	_fields_ = [
		("hdr", xfs_dir2_sf_hdr),
		("list", xfs_dir2_sf_entry * 1)
	]

class xfs_dinode(Structure):
	_fields_ = [
		("di_magic", c_uint16),
		("di_mode", c_uint16),
		("di_version", c_uint8),
		("di_format", c_uint8),
		("di_onlink", c_uint16),
		("di_uid", c_uint32),
		("di_gid", c_uint32),
		("di_nlink", c_uint32),
		("di_projid_lo", c_uint16),
		("di_projid_hi", c_uint16),
		("di_pad", c_uint8 * 6),
		("di_flushiter", c_uint16),
		("di_atime", xfs_timestamp),
		("di_mtime", xfs_timestamp),
		("di_ctime", xfs_timestamp),
		("di_size", xfs_fsize),
		("di_nblocks", xfs_rfsblock),
		("di_extsize", xfs_extlen),
		("di_nextents", xfs_extnum),
		("di_anextents", xfs_aextnum),
		("di_forkoff", c_uint8),
		("di_aformat", c_int8),
		("di_dmevmask", c_uint32),
		("di_dmstate", c_uint16),
		("di_flags", c_uint16),
		("di_gen", c_uint32),
		("di_next_unlinked", c_uint32),
		("di_crc", c_uint32),
		("di_changecount", c_uint64),
		("di_lsn", xfs_lsn),
		("di_flags2", c_uint64),
		("di_cowextsize", c_uint32),
		("di_pad2", c_uint8 * 12),
		("di_crtime", xfs_timestamp),
		("di_ino", c_uint64),
		("di_uuid", uuid)
	]
	def size(self):
		if self.di_version == 0x3:
			return sizeof(xfs_dinode)
		else:
			return xfs_dinode.di_crc.offset

class xfs_v2_flush_counter_struct(Structure):
	_fields_ = [
		("di_v2_pad", c_uint8 * 6),
		("di_flushiter", c_uint16),
	]

class xfs_big_nextents_union(Union):
	_fields_ = [
		("di_big_nextents", c_uint64),
		("di_v3_pad", c_uint64),
		("di_v2", xfs_v2_flush_counter_struct)
	]

class xfs_nextents_struct(Structure):
	_pack_ = 1
	_fields_ = [
		("di_nextents", xfs_extnum),
		("di_anextents", xfs_aextnum),
	]

class xfs_big_nextents_struct(Structure):
	_pack_ = 1
	_fields_ = [
		("di_big_anextents", xfs_extnum),
		("di_nrext64_pad", xfs_aextnum),
	]

class xfs_nextents_union(Union):
	_pack_ = 1
	_fields_ = [
		("di_nextents_struct", xfs_nextents_struct),
		("di_big_nextents_struct", xfs_big_nextents_struct),
	]

class xfs_log_dinode(Structure):
	_fields_ = [
		("di_magic", c_uint16),
		("di_mode", c_uint16),
		("di_version", c_uint8),
		("di_format", c_uint8),
		("di_metatype", c_uint16),
		("di_uid", c_uint32),
		("di_gid", c_uint32),
		("di_nlink", c_uint32),
		("di_projid_lo", c_uint16),
		("di_projid_hi", c_uint16),
		("di_big_nextents_union", xfs_big_nextents_union),
		("di_atime", xfs_timestamp),
		("di_mtime", xfs_timestamp),
		("di_ctime", xfs_timestamp),
		("di_size", xfs_fsize),
		("di_nblocks", xfs_rfsblock),
		("di_extsize", xfs_extlen),
		("di_nextents_union", xfs_nextents_union),
		("di_forkoff", c_uint8),
		("di_aformat", c_int8),
		("di_dmevmask", c_uint32),
		("di_dmstate", c_uint16),
		("di_flags", c_uint16),
		("di_gen", c_uint32),
		("di_next_unlinked", xfs_agino),
		("di_crc", c_uint32),
		("di_changecount", c_uint64),
		("di_lsn", xfs_agino),
		("di_flags2", c_uint64),
		("di_cowextsize", c_uint32),
		("di_pad2", c_uint8 * 12),
		("di_crtime", xfs_timestamp),
		("di_ino", xfs_ino),
		("di_uuid", uuid)
	]

class xfs_bmbt_key(Structure):
	_fields_= [
		("br_startoff", c_uint64)
	]
xfs_bmdr_key = xfs_bmbt_key

class xfs_bmbt_rec_32(Structure):
	_fields_ = [
		("l0", c_uint32),
		("l1", c_uint32),
		("l2", c_uint32),
		("l3", c_uint32),
	]

class xfs_bmbt_rec_64(Structure):
	_fields_ = [
		("l0", c_uint64),
		("l1", c_uint64)
	]
xfs_bmbt_rec = xfs_bmbt_rec_64
xfs_bmdr_rec = xfs_bmbt_rec

class xfs_bmbt_irec(Structure):
	_fields_ = [
		("br_startoff", xfs_fileoff),
		("br_startblock", xfs_fsblock),
		("br_blockcount", xfs_filblks),
		("br_state", c_int32)
	]

class xfs_alloc_rec(Structure):
	_fields_ = [
		("ar_statblock", c_uint64),
		("ar_blockcount", c_uint64)
	]

class xfs_agi(Structure):
	_fields_ = [
		("agi_magicnum", c_uint32),
		("agi_versionnum", c_uint32),
		("agi_seqno", c_uint32),
		("agi_length", c_uint32),
		("agi_count", c_uint32),
		("agi_root", c_uint32),
		("agi_level", c_uint32),
		("agi_freecount", c_uint32),
		("agi_newino", c_uint32),
		("agi_dirino", c_uint32),
		("agi_unlinked", c_uint32 * XFS_AGI_UNLINKED_BUCKETS),
		("agi_uuid", uuid),
		("agi_crc", c_uint32),
		("agi_pad32", c_uint32),
		("agi_lsn", c_uint64),
		("agi_free_root", c_uint32),
		("agi_free_level", c_uint32),
		("agi_iblocks", c_uint32),
		("agi_fblocks", c_uint32)
	]

class xfs_agf(Structure):
	_fields_ = [
		("agf_magicnum", c_uint32),
		("agf_versionnum", c_uint32),
		("agf_seqno", c_uint32),
		("agf_length", c_uint32),
		("agf_bno_root", c_uint32),
		("agf_cnt_root", c_uint32),
		("agf_rmap_root", c_uint32),
		("agf_bno_level", c_uint32),
		("agf_cnt_level", c_uint32),
		("agf_rmap_level", c_uint32),
		("agf_flfirst", c_uint32),
		("agf_fllast", c_uint32),
		("agf_flcount", c_uint32),
		("agf_freeblks", c_uint32),
		("agf_longest", c_uint32),
		("agf_btreeblks", c_uint32),
		("agf_uuid", uuid),
		("agf_rmap_blocks", c_uint32),
		("agf_refcount_blocks", c_uint32),
		("agf_refcount_root", c_uint32),
		("agf_refcount_level", c_uint32),
		("agf_spare64", c_uint64 * 14),
		("", c_uint64),
		("", c_uint32),
		("", c_uint32),
	]

class xfs_disk_dquot(Structure):
	_fields_ = [
		("d_magic", c_uint16),
		("d_version", c_uint8),
		("d_type", c_uint8),
		("d_id", c_uint32),
		("d_blk_hardlimit", c_uint64),
		("d_blk_softlimit", c_uint64),
		("d_ino_hardlimit", c_uint64),
		("d_ino_softlimit", c_uint64),
		("d_bcount", c_uint64),
		("d_icount", c_uint64),
		("d_itimer", c_uint32),
		("d_btimer", c_uint32),
		("d_iwarns", c_uint16),
		("d_bwarns", c_uint16),
		("d_pad0", c_uint32),
		("d_rtb_hardlimit", c_uint64),
		("d_rtb_softlimit", c_uint64),
		("d_rtbcount", c_uint64),
		("d_rtbtimer", c_uint32),
		("d_rtbwarns", c_uint16),
		("d_pad", c_uint16)
	]

class xfs_sb(Structure):
	_fields_ = [
		("sb_magicnum", c_uint32),
		("sb_blocksize", c_uint32),
		("sb_dblocks", xfs_rfsblock),
		("sb_rblocks", xfs_rfsblock),
		("sb_rextents", xfs_rtblock),
		("sb_uuid", uuid),
		("sb_logstart", xfs_fsblock),
		("sb_rootino", xfs_ino),
		("sb_rbmino", xfs_ino),
		("sb_rsumino", xfs_ino),
		("sb_rextsize", xfs_agblock),
		("sb_agblocks", xfs_agblock),
		("sb_agcount", xfs_agnumber),
		("sb_rbmblocks", xfs_extlen),
		("sb_logblocks", xfs_extlen),
		("sb_versionnum", c_uint16),
		("sb_sectsize", c_uint16),
		("sb_inodesize", c_uint16),
		("sb_inopblock", c_uint16),
		("sb_fname", c_char * XFSLABEL_MAX),
		("sb_blocklog", c_uint8),
		("sb_sectlog", c_uint8),
		("sb_inodelog", c_uint8),
		("sb_inopblog", c_uint8),
		("sb_agblklog", c_uint8),
		("sb_rextslog",c_uint8),
		("sb_inprogress", c_uint8),
		("sb_imax_pct", c_uint8),
		("sb_icount", c_uint64),
		("sb_ifree", c_uint64),
		("sb_fdblocks", c_uint64),
		("sb_frextents", c_uint64),
		("sb_uquotino", xfs_ino),
		("sb_gquotino", xfs_ino),
		("sb_qflags", c_uint16),
		("sb_flags", c_uint8),
		("sb_shared_vn", c_uint8),
		("sb_inoalignmt", xfs_extlen),
		("sb_unit", c_uint32),
		("sb_width", c_uint32),
		("sb_dirblklog", c_uint8),
		("sb_logsectlog", c_uint8),
		("sb_logsectsize", c_uint16),
		("sb_logsunit", c_uint32),
		("sb_features2", c_uint32),
		("sb_bad_features2", c_uint32),
		("sb_features_compat", c_uint32),
		("sb_features_ro_compat", c_uint32),
		("sb_features_incompat", c_uint32),
		("sb_features_log_incompat", c_uint32),
		("sb_crc", c_uint32),
		("sb_spino_align", xfs_extlen),
		("sb_pquotino", xfs_ino),
		("sb_lsn", xfs_lsn),
		("sb_meta_uuid", uuid),
		("sb_metadirino", xfs_ino),
		("sb_rgcount", xfs_rgnumber),
		("sb_rgextents", xfs_rtxlen),
		("sb_rgblklog", c_uint8),
		("sb_pad", c_uint8 * 7)
	]

class xfs_dsb(Structure):
	_fields_ = [
		("sb_magicnum", c_uint32),
		("sb_blocksize", c_uint32),
		("sb_dblocks", c_uint64),
		("sb_rblocks", c_uint64),
		("sb_rextents", c_uint64),
		("sb_uuid", uuid),
		("sb_logstart", c_uint64),
		("sb_rootino", c_uint64),
		("sb_rbmino", c_uint64),
		("sb_rsumino", c_uint64),
		("sb_rextsize", c_uint32),
		("sb_agblocks", c_uint32),
		("sb_agcount", c_uint32),
		("sb_rbmblocks", c_uint32),
		("sb_logblocks", c_uint32),
		("sb_versionnum", c_uint16),
		("sb_sectsize", c_uint16),
		("sb_inodesize", c_uint16),
		("sb_inopblock", c_uint16),
		("sb_fname", c_char * XFSLABEL_MAX),
		("sb_blocklog", c_uint8),
		("sb_sectlog", c_uint8),
		("sb_inodelog", c_uint8),
		("sb_inopblog", c_uint8),
		("sb_agblklog", c_uint8),
		("sb_rextslog",c_uint8),
		("sb_inprogress", c_uint8),
		("sb_imax_pct", c_uint8),
		("sb_icount", c_uint64),
		("sb_ifree", c_uint64),
		("sb_fdblocks", c_uint64),
		("sb_frextents", c_uint64),
		("sb_uquotino", c_uint64),
		("sb_gquotino", c_uint64),
		("sb_qflags", c_uint16),
		("sb_flags", c_uint8),
		("sb_shared_vn", c_uint8),
		("sb_inoalignmt", c_uint32),
		("sb_unit", c_uint32),
		("sb_width", c_uint32),
		("sb_dirblklog", c_uint8),
		("sb_logsectlog", c_uint8),
		("sb_logsectsize", c_uint16),
		("sb_logsunit", c_uint32),
		("sb_features2", c_uint32),
		("sb_bad_features2", c_uint32),
		("sb_features_compat", c_uint32),
		("sb_features_ro_compat", c_uint32),
		("sb_features_incompat", c_uint32),
		("sb_features_log_incompat", c_uint32),
		("sb_crc", c_uint32),
		("sb_spino_align", c_uint32),
		("sb_pquotino", c_uint64),
		("sb_lsn", c_uint64),
		("sb_meta_uuid", uuid),
		("sb_metadirino", c_uint64),
		("sb_rgcount", c_uint32),
		("sb_rgextents", c_uint32),
		("sb_rgblklog", c_uint8),
		("sb_pad", c_uint8 * 7)
	]

class xfs_bmdr_block(Structure):
	_fields_ = [
		("bb_level", c_uint16),
		("bb_numrecs", c_uint16)
	]

class xfs_btree_lblock(Structure):
	_fields_ = [
		("bb_magic", c_uint32),
		("bb_level", c_uint16),
		("bb_numrecs", c_uint16),
		("bb_leftsib", c_uint64),
		("bb_rightsib", c_uint64),
		("bb_blkno", c_uint64),
		("bb_lsn", c_uint64),
		("bb_uuid", uuid),
		("bb_owner", c_uint64),
		("bb_crc", c_uint32),
		("bb_pad", c_uint32)
	]
xfs_bmbt_block = xfs_btree_lblock

class xfs_dir2_leaf_tail(Structure):
	_fields_ = [
		("bestcount", c_uint32)
	]

class xfs_da_blkinfo(Structure):
	_fields_ = [
		("forw", c_uint32),
		("back", c_uint32),
		("magic", c_uint16),
		("pad", c_uint16)
	]

class xfs_dir2_leaf_entry(Structure):
	_fields_ = [
		("hashval", c_uint32),
		("address", c_uint32)
	]

class xfs_dir2_leaf_hdr(Structure):
	_fields_ = [
		("info", xfs_da_blkinfo),
		("count", c_uint16),
		("stale", c_uint16)
	]

class xfs_da3_blkinfo(Structure):
	_fields_ = [
		("hdr", xfs_da_blkinfo),
		("crc", c_uint32),
		("blkno", c_uint64),
		("lsn", c_uint64),
		("uuid", uuid),
		("owner", c_uint64),
	]

class xfs_dir3_leaf_hdr(Structure):
	_fields_ = [
		("info", xfs_da3_blkinfo),
		("count", c_uint16),
		("stale", c_uint16),
		("pad", c_uint32)
	]

class xfs_dir2_data_free(Structure):
	_fields_ = [
		("offset", c_uint16),
		("length", c_uint16)
	]

class xfs_dir2_data_entry(Structure):
	_fields_ = [
		("inumber", c_uint64),
		("namelen", c_uint8),
		("name", c_uint8 * 1)
	]

class xfs_dir2_data_unused(Structure):
	_fields_ = [
		("freetag", c_uint16),
		("length", c_uint16),
		("tag", c_uint16)
	]

class xfs_dir2_block_tail(Structure):
	_fields_ = [
		("count", c_uint32),
		("stale", c_uint32)
	]

class xfs_dir2_data_hdr(Structure):
	_fields_ = [
		("magic", c_uint32),
		("bestfree", xfs_dir2_data_free * XFS_DIR2_DATA_FD_COUNT)
	]

class xfs_dir2_data_union(Union):
	_fields_ = [
		("entry", xfs_dir2_data_entry),
		("unused", xfs_dir2_data_unused)
	]

class xfs_dir2_data(Structure):
	_fields_ = [
		("hdr", xfs_dir2_data_hdr),
		("u", xfs_dir2_data_union * 1)
	]

class xfs_dir3_blk_hdr(Structure):
	_fields_ = [
		("magic", c_uint32),
		("crc", c_uint32),
		("blkno", c_uint64),
		("lsn", c_uint64),
		("uuid", uuid),
		("owner", c_uint64)
	]

class xfs_dir3_data_hdr(Structure):
	_fields_ = [
		("hdr", xfs_dir3_blk_hdr),
		("best_free", xfs_dir2_data_free * XFS_DIR2_DATA_FD_COUNT),
		("pad", c_uint32)
	]

class xfs_dir2_block(Structure):
	_fields_ = [
		("hdr", xfs_dir2_data_hdr),
		("u", xfs_dir2_data_union * 1),
		("l", xfs_dir2_leaf_entry * 1),
		("tail", xfs_dir2_block_tail)
	]

class xfs_attr_sf_hdr(Structure):
	_fields_ = [
		("totsize", c_uint16),
		("count", c_uint8),
		("padding", c_uint8)
	]

class xfs_attr_sf_entry(Structure):
	_fields_ = [
		("namelen", c_uint8),
		("valuelen", c_uint8),
		("flags", c_uint8),
		("nameval", c_uint8 * 1)
	]

class xlog_rec_header(Structure):
	_fields_ = [
		("h_magicno", c_uint32),
		("h_cycle", c_uint32),
		("h_version", c_uint32),
		("h_len", c_uint32),
		("h_lsn", c_uint64),
		("h_tail_lsn", c_uint64),
		("h_crc", c_uint32),
		("h_prev_block", c_uint32),
		("h_num_logops", c_uint32),
		("h_cycle_data", c_uint32 * (XLOG_HEADER_CYCLE_SIZE // BBSIZE)),
		("h_fmt", c_uint32),
		("h_fs_uuid", uuid),
		("h_size", c_uint32)
	]

class xfs_blft(IntEnum):
	XFS_BLFT_UNKNOWN_BUF = 0
	XFS_BLFT_UDQUOT_BUF = 1
	XFS_BLFT_PDQUOT_BUF = 2
	XFS_BLFT_GDQUOT_BUF = 3
	XFS_BLFT_BTREE_BUF = 4
	XFS_BLFT_AGF_BUF = 5
	XFS_BLFT_AGFL_BUF = 6
	XFS_BLFT_AGI_BUF = 7
	XFS_BLFT_DINO_BUF = 8
	XFS_BLFT_SYMLINK_BUF = 9
	XFS_BLFT_DIR_BLOCK_BUF = 10
	XFS_BLFT_DIR_DATA_BUF = 11
	XFS_BLFT_DIR_FREE_BUF = 12
	XFS_BLFT_DIR_LEAF1_BUF = 13
	XFS_BLFT_DIR_LEAFN_BUF = 14
	XFS_BLFT_DA_NODE_BUF = 15
	XFS_BLFT_ATTR_LEAF_BUF = 16
	XFS_BLFT_ATTR_RMT_BUF = 17
	XFS_BLFT_SB_BUF = 18
	XFS_BLFT_RTBITMAP_BUF = 19
	XFS_BLFT_RTSUMMARY_BUF = 20
	XFS_BLFT_MAX_BUF = 1 << XFS_BLFT_BITS

class xfs_inode_log_format_64_union(Union):
	_fields_ = [
		("ilfu_rdev", c_uint32),
		("ilfu_uuid", uuid)
	]

class xfs_icreate_log(Structure):
	_fields_ = [
		("icl_type", c_uint16),
		("icl_size", c_uint16),
		("icl_ag", c_int32),
		("icl_agbno", c_int32),
		("icl_count", c_int32),
		("icl_isize", c_int32),
		("icl_length", c_int32),
		("icl_gen", c_int32)
	]

class xfs_buf_log_format(Structure):
	_fields_ = [
		("blf_type", c_ushort),
		("blf_size", c_ushort),
		("blf_flags", c_ushort),
		("blf_len", c_ushort),
		("blf_blkno", c_int64),
		("blf_map_size", c_uint32),
		("blf_data_map", c_uint32 * XFS_BLF_DATAMAP_SIZE)
	]

class xfs_inode_log_format_32(Structure):
	_pack_ = 1
	_fields_ = [
		("ilf_type", c_uint16),
		("ilf_size", c_uint16),
		("ilf_fields", c_uint32),
		("ilf_asize", c_uint16),
		("ilf_dsize", c_uint16),
		("ilf_ino", c_uint64),
		("ilf_u", xfs_inode_log_format_64_union),
		("ilf_blkno", c_int64),
		("ilf_len", c_int32),
		("ilf_boffset", c_int32)
	]

class xfs_inode_log_format_64(Structure):
	_fields_ = [
		("ilf_type", c_uint16),
		("ilf_size", c_uint16),
		("ilf_fields", c_uint32),
		("ilf_asize", c_uint16),
		("ilf_dsize", c_uint16),
		("ilf_pad", c_uint32),
		("ilf_ino", c_uint64),
		("ilf_u", xfs_inode_log_format_64_union),
		("ilf_blkno", c_int64),
		("ilf_len", c_int32),
		("ilf_boffset", c_int32)
	]
xfs_inode_log_format = xfs_inode_log_format_64

class xfs_log_items(Structure):
	_fields_ = [
		("magic", c_uint16),
		("size", c_uint16)
	]

class xfs_trans_header(Structure):
	_fields_ = [
		("th_magic", c_uint32),
		("th_type", c_uint32),
		("th_tid", c_int32),
		("th_num_items", c_uint32)
	]

class xlog_op_header(Structure):
	_fields_ = [
		("oh_tid", c_uint32),
		("oh_len", c_uint32),
		("oh_clientid", c_uint8),
		("oh_flags", c_uint8),
		("oh_res2", c_uint16)
	]

class xlog_split_item:
	def __init__(self):
		self.si_next = None
		self.si_prev = None
		self.si_xtid = 0x0
		self.si_skip = 0

class xlog_rec_ext_header(Structure):
	_fields_ = [
		("xh_cycle", c_uint32),
		("xh_cycle_data", c_uint32 * (XLOG_HEADER_CYCLE_SIZE // BBSIZE))
	]

class xfs_det_headers(Union):
	_fields_ = [
		("xlog_rec_header", xlog_rec_header),
		("xlog_op_header", xlog_op_header),
		("xfs_trans_header", xfs_trans_header),
		("xfs_log_items", xfs_log_items)
	]

class sig_union(Union):
	_fields_ = [
		("sig8", c_uint8),
		("sig16", c_uint16),
		("sig32", c_uint32),
		("sig64", c_uint64),
	]

def BLOCK_LSN(lsn):
	return 0x00000000ffffffff & lsn

def XLOG_TOTAL_REC_SHIFT(m_features):
	if xfs_has_logv2(m_features):
		return BTOBB(XLOG_MAX_ICLOGS << XLOG_MAX_RECORD_BSHIFT)
	else:
		return BTOBB(XLOG_MAX_ICLOGS << XLOG_BIG_RECORD_BSHIFT)

def BLK_AVG(blk1, blk2):
	return ((blk1 + blk2) >> 1)

def LIBXFS_BBTOOFF64(bbs):
	return (((bbs)) << BBSHIFT)

def BTOBB(bytes):
	return (((bytes) + BBSIZE - 1) >> BBSHIFT)

def UUCMP(u1, u2):
	if u1 == u2:
		return 0
	if u1 < u2:
		return -1
	else:
		return 1

def XFS_FSB_TO_BB(sb_logblocks, blkbb_log):
	return sb_logblocks << blkbb_log

def XFS_FSB_TO_DADDR(fsbno, sb_agblocks, sb_agblklog, blkbb_log):
	return XFS_AGB_TO_DADDR(sb_agblocks, blkbb_log, XFS_FSB_TO_AGNO(sb_agblklog, fsbno), XFS_FSB_TO_AGBNO(sb_agblklog, fsbno))

def XFS_AGB_TO_DADDR(sb_agblocks, blkbb_log, agno, agbno):
	return XFS_FSB_TO_BB(agno * sb_agblocks + agbno, blkbb_log)

def XFS_FSB_TO_AGNO(sb_agblklog, fsbno):
	return fsbno >> sb_agblklog

def XFS_FSB_TO_AGBNO(sb_agblklog, fsbno):
	return fsbno & xfs_mask32lo(sb_agblklog)

def BBTOOFF64(bbs):
	return (bbs) << BBSHIFT

def BBTOB(bbs):
	return (bbs) << BBSHIFT

def XFS_SB_VERSION_NUM(sb_versionnum):
	return cpu_to_be16(sb_versionnum) & XFS_SB_VERSION_NUMBITS

def XFS_LITINO(sb_inodesize, di_version):
	return sb_inodesize - xfs_dinode_size(di_version)

def XFS_DFORK_Q(di_forkoff):
	return (di_forkoff != 0)

def XFS_DFORK_BOFF(di_forkoff):
	return (di_forkoff << 3)

def XFS_DFORK_DSIZE(di_forkoff, sb_inodesize, di_version):
	if XFS_DFORK_Q(di_forkoff):
		return XFS_DFORK_BOFF(di_forkoff)
	else:
		return XFS_LITINO(sb_inodesize, di_version)

def XFS_DFORK_ASIZE(di_forkoff, sb_inodesize, di_version):
	if XFS_DFORK_Q(di_forkoff):
		return XFS_LITINO(di_forkoff, di_version) - XFS_DFORK_BOFF(di_forkoff)
	else:
		return 0

def XFS_DFORK_SIZE(di_forkoff, sb_inodesize, di_version, w):
	if w == XFS_DATA_FORK:
		return XFS_DFORK_DSIZE(di_forkoff, sb_inodesize, di_version)
	else:
		return XFS_DFORK_ASIZE(di_forkoff, sb_inodesize, di_version)

def New(src, target):
	_c = cast(src, POINTER(target)).contents
	return _c

def _to_cpu(val, bytes):
	_v = 0
	if sys.byteorder == "little":
		_val = val.to_bytes(bytes, byteorder=sys.byteorder)
		for i in range(len(_val)):
			_v = _v + (_val[len(_val)-1-i] << 8*i)
	else:
		_v = val
	return _v

def _cpu_to_be(val, bytes):
	_v = 0
	if sys.byteorder == "little":
		_val = val.to_bytes(bytes,byteorder=sys.byteorder)
		for i in range(len(_val)):
			_v = _v + (_val[len(_val)-1-i] << 8*i)
	else:
		_v = val
	return _v

def _cpu_to_le(val, bytes):
	_v = 0
	if sys.byteorder == "big":
		_val = val.to_bytes(bytes,byteorder=sys.byteorder)
		for i in range(len(_val)):
			_v = _v + (_val[len(_val)-1-i] << 8*i)
	else:
		_v = val
	return _v

def be64_to_cpu(val):
	if val < 0:
		val = val & 0xffffffffffffffff
	return _to_cpu(val, 8)

def be32_to_cpu(val):
	if val < 0:
		val = val & 0xffffffff
	return _to_cpu(val, 4)

def be16_to_cpu(val):
	if val < 0:
		val = val & 0xffff
	return _to_cpu(val, 2)

def cpu_to_be16(val):
	if val < 0:
		val = val & 0xffff
	return _cpu_to_be(val, 2)

def cpu_to_be32(val):
	if val < 0:
		val = val & 0xffffffff
	return _cpu_to_be(val, 4)

def cpu_to_be64(val):
	if val < 0:
		val = val & 0xffffffffffffffff
	return _cpu_to_be(val, 8)

def conv_be64(b):
	_val = 0
	for i in range(8):
		_val = _val + (b[7-i]<<i*8)

	return _val

def cpu_to_le32(val):
	if val < 0:
		val = val & 0xffffffff
	return _cpu_to_le(val, 4)

def roundup(x, y):
	return ((((x)+((y) - 1)) // (y)) * (y))

def howmany(x, y):
	return (((x)+((y)-1))//(y))

def uuid_unpack(uu):
	
	uuid = u_uuid()
	_tmp = uu.u_bits[0]
	_tmp = (_tmp << 8) | uu.u_bits[1]
	_tmp = (_tmp << 8) | uu.u_bits[2]
	_tmp = (_tmp << 8) | uu.u_bits[3]
	uuid.time_low = _tmp
	
	_tmp = uu.u_bits[4]
	_tmp = (_tmp << 8) | uu.u_bits[5]
	uuid.time_mid = _tmp
	
	_tmp = uu.u_bits[6]
	_tmp = (_tmp << 8) | uu.u_bits[7]
	uuid.time_hi_and_version = _tmp
	
	_tmp = uu.u_bits[8]
	_tmp = (_tmp << 8) | uu.u_bits[9]
	uuid.clock_seq = _tmp

	for _i in range(len(uuid.node)):
		uuid.node[_i] = uu.u_bits[10+_i]

	return uuid

def uuid_compare(uu1, uu2):

	uuid1 = uuid_unpack(uu1)
	uuid2 = uuid_unpack(uu2)
	_r = UUCMP(uuid1.time_low, uuid2.time_low)
	if _r != 0:
		return _r

	_r = UUCMP(uuid1.time_mid, uuid2.time_mid)
	if _r != 0:
		return _r

	_r = UUCMP(uuid1.time_hi_and_version, uuid2.time_hi_and_version)
	if _r != 0:
		return _r

	_r = UUCMP(uuid1.clock_seq, uuid2.clock_seq)
	if _r != 0:
		return _r

	for _i in range(len(uuid1.node)):
		if uuid1.node[_i] != uuid2.node[_i]:
			return _i

	return 0

def platform_uuid_compare(uu1, uu2):
	return uuid_compare(uu1, uu2)

def uuid_unparse(uu):
	uuid = ""
	for _i in range(len(uu.u_bits)):
		if _i == 4 or _i == 6 or _i == 8 or _i == 10:
			uuid = uuid + "-"
		uuid = uuid + "{0:x}".format(uu.u_bits[_i])
	return uuid

def platform_uuid_unparse(uu):
	return uuid_unparse(uu)

def header_check_uuid(sb, head):
	if not platform_uuid_compare(sb.sb_uuid, head.h_fs_uuid):
		return 0
	return 1

def uuid_is_null(uu):
	for _u in uu.u_bits:
		if _u != 0x00:
			return False
	return True

def platform_uuid_is_null(uu):
	return uuid_is_null(uu)

def get_unaligned_be32(ptr):
	return ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3]

def get_unaligned_be64(ptr):
	return get_unaligned_be32(ptr) << 32 | get_unaligned_be32(ptr[4:])

def get_type(mode, is_bigendian = True):
	if is_bigendian:
		_m = cpu_to_be16(mode) & S_IFMT
	else:
		_m = mode & S_IFMT
	return _m

def get_uuid(uuid):
	_uuid = ""
	for _u in uuid.u_bits:
		_uuid = _uuid + "{0:x}".format(_u)
	return _uuid

def xfs_sb_is_v5(sb):
	return XFS_SB_VERSION_NUM(sb.sb_versionnum) == XFS_SB_VERSION_5

def xfs_sb_version_to_features(sb):

	features = 0 & 0xffffffffffffffff
	if cpu_to_be64(sb.sb_rblocks) > 0:
		features |= XFS_FEAT_REALTIME
	if (cpu_to_be16(sb.sb_versionnum) & XFS_SB_VERSION_NLINKBIT):
		features |= XFS_FEAT_NLINK
	if (cpu_to_be16(sb.sb_versionnum) & XFS_SB_VERSION_ATTRBIT):
		features |= XFS_FEAT_ATTR
	if (cpu_to_be16(sb.sb_versionnum) & XFS_SB_VERSION_QUOTABIT):
		features |= XFS_FEAT_QUOTA
	if (cpu_to_be16(sb.sb_versionnum) & XFS_SB_VERSION_ALIGNBIT):
		features |= XFS_FEAT_ALIGN
	if (cpu_to_be16(sb.sb_versionnum) & XFS_SB_VERSION_LOGV2BIT):
		features |= XFS_FEAT_LOGV2
	if (cpu_to_be16(sb.sb_versionnum) & XFS_SB_VERSION_DALIGNBIT):
		features |= XFS_FEAT_DALIGN
	if (cpu_to_be16(sb.sb_versionnum) & XFS_SB_VERSION_EXTFLGBIT):
		features |= XFS_FEAT_EXTFLG
	if (cpu_to_be16(sb.sb_versionnum) & XFS_SB_VERSION_SECTORBIT):
		features |= XFS_FEAT_SECTOR
	if (cpu_to_be16(sb.sb_versionnum) & XFS_SB_VERSION_BORGBIT):
		features |= XFS_FEAT_ASCIICI
	if (cpu_to_be16(sb.sb_versionnum) & XFS_SB_VERSION_MOREBITSBIT):
		if (cpu_to_be32(sb.sb_features2) & XFS_SB_VERSION2_LAZYSBCOUNTBIT):
			features |= XFS_FEAT_LAZYSBCOUNT
		if (cpu_to_be32(sb.sb_features2) & XFS_SB_VERSION2_ATTR2BIT):
			features |= XFS_FEAT_ATTR2
		if (cpu_to_be32(sb.sb_features2) & XFS_SB_VERSION2_PROJID32BIT):
			features |= XFS_FEAT_PROJID32
		if (cpu_to_be32(sb.sb_features2) & XFS_SB_VERSION2_FTYPE):
			features |= XFS_FEAT_FTYPE
	if not xfs_sb_is_v5(sb):
		return features

	features |= (XFS_FEAT_ALIGN | XFS_FEAT_LOGV2 | XFS_FEAT_EXTFLG | \
				XFS_FEAT_LAZYSBCOUNT | XFS_FEAT_ATTR2 | XFS_FEAT_PROJID32 | \
				XFS_FEAT_V3INODES | XFS_FEAT_CRC | XFS_FEAT_PQUOTINO)
	if (cpu_to_be32(sb.sb_features_ro_compat) & XFS_SB_FEAT_RO_COMPAT_FINOBT):
		features |= XFS_FEAT_FINOBT
	if (cpu_to_be32(sb.sb_features_ro_compat) & XFS_SB_FEAT_RO_COMPAT_RMAPBT):
		features |= XFS_FEAT_RMAPBT
	if (cpu_to_be32(sb.sb_features_ro_compat) & XFS_SB_FEAT_RO_COMPAT_REFLINK):
		features |= XFS_FEAT_REFLINK
	if (cpu_to_be32(sb.sb_features_ro_compat) & XFS_SB_FEAT_RO_COMPAT_INOBTCNT):
		features |= XFS_FEAT_INOBTCNT
	if (cpu_to_be32(sb.sb_features_incompat) & XFS_SB_FEAT_INCOMPAT_FTYPE):
		features |= XFS_FEAT_FTYPE
	if (cpu_to_be32(sb.sb_features_incompat) & XFS_SB_FEAT_INCOMPAT_SPINODES):
		features |= XFS_FEAT_SPINODES
	if (cpu_to_be32(sb.sb_features_incompat) & XFS_SB_FEAT_INCOMPAT_META_UUID):
		features |= XFS_FEAT_META_UUID
	if (cpu_to_be32(sb.sb_features_incompat) & XFS_SB_FEAT_INCOMPAT_BIGTIME):
		features |= XFS_FEAT_BIGTIME
	if (cpu_to_be32(sb.sb_features_incompat) & XFS_SB_FEAT_INCOMPAT_NEEDSREPAIR):
		features |= XFS_FEAT_NEEDSREPAIR
	if (cpu_to_be32(sb.sb_features_incompat) & XFS_SB_FEAT_INCOMPAT_NREXT64):
		features |= XFS_FEAT_NREXT64

	return features

def xfs_has_ftype(m_features):
	return (m_features & XFS_FEAT_FTYPE)

def xfs_has_logv2(m_features):
	return (m_features & XFS_FEAT_LOGV2)

def xfs_has_v3inodes(m_features):
	return (m_features & XFS_FEAT_V3INODES)

def xfs_mask32lo(n):
	return ((1 &  0xffffffff) << (n)) - 1

def xfs_log_dinode_size(m_features):
	if xfs_has_v3inodes(m_features):
		return sizeof(xfs_log_dinode)
	else:
		return xfs_log_dinode.di_next_unlinked.offset

def xfs_dinode_size(version):
	_size = sizeof(xfs_dinode)
	if version == 0x3:
		return sizeof(xfs_dinode)
	else:
		return xfs_dinode.di_crc.offset

def xfs_mask64lo(n):
	return ((1 &  0xffffffffffffffff) << (n)) - 1

def xfs_bmdr_maxrecs(blocklen, is_leaf):
	blocklen -= sizeof(xfs_bmdr_block)
	if is_leaf:
		return blocklen // sizeof(xfs_bmdr_rec)
	return blocklen // (sizeof(xfs_bmdr_key) + sizeof(xfs_bmdr_ptr))

def xfs_dinode_has_bigtime(version, flags2, is_bigendian = True):
	if version < 0x3:
		return False
	if is_bigendian:
		return flags2 & cpu_to_be64(XFS_DIFLAG2_BIGTIME)
	else:
		return flags2 & XFS_DIFLAG2_BIGTIME

def unpack_bmbt_rec(bmbt_rec, is_bigendian = True):

	if is_bigendian:
		l0 = cpu_to_be64(bmbt_rec.l0)
		l1 = cpu_to_be64(bmbt_rec.l1)
	else:
		l0 = bmbt_rec.l1
		l1 = bmbt_rec.l0

	bmbt_irec = xfs_bmbt_irec()
	bmbt_irec.br_startoff = (l0 & xfs_mask64lo(64 - BMBT_EXNTFLAG_BITLEN)) >> 9
	bmbt_irec.br_startblock = ((l0 & xfs_mask64lo(9)) << 43) | (l1 >> 21)
	bmbt_irec.br_blockcount = l1 & xfs_mask64lo(21)

	if l0 >> (64 - BMBT_EXNTFLAG_BITLEN):
		bmbt_irec.br_state = xfs_exntst_enum.XFS_EXT_UNWRITTEN
	else:
		bmbt_irec.br_state = xfs_exntst_enum.XFS_EXT_NORM

	return bmbt_irec

def array_to_num(arr):
	_num = 0
	for _i in range(len(arr)):
		_num += arr[_i] << ((len(arr)-1-_i) * 8)
	return _num

def timestamp_to_str(timestamp, is_bigendian = True):

	if is_bigendian:
		_time = (cpu_to_be32(timestamp.t_sec) << 32) + cpu_to_be32(timestamp.t_nsec)
		_epoch = _time // NSEC_PER_SEC
		_nano = _time % NSEC_PER_SEC
		_epoch = _epoch - XFS_BIGTIME_EPOCH_OFFSET
		_t = get_utc_str(_epoch)
		_timestamp = _t.split("+")[0] + "." + str(_nano).zfill(9)
	else:
		_t = timestamp.t_nsec
		timestamp.t_nsec = timestamp.t_sec
		timestamp.t_sec = _t
		_time = (timestamp.t_sec << 32) + timestamp.t_nsec
		_epoch = _time // NSEC_PER_SEC
		_nano = _time % NSEC_PER_SEC
		_epoch = _epoch - XFS_BIGTIME_EPOCH_OFFSET
		_t = get_utc_str(_epoch)
		_timestamp = _t.split("+")[0] + "." + str(_nano).zfill(9)

	return _timestamp

def legacy_timestamp_to_str(timestamp, is_bigendian = True):

	if is_bigendian:
		_t = get_utc_str(cpu_to_be32(timestamp.t_sec))
		_timestamp = _t.split("+")[0] + "." + str(cpu_to_be32(timestamp.t_nsec)).zfill(9)
	else:
		_t = get_utc_str(timestamp.t_sec)
		_timestamp = _t.split("+")[0] + "." + str(timestamp.t_nsec).zfill(9)
	
	return _timestamp

def get_utc_str(epoch):

	try:
		_utc = str((datetime.datetime.fromtimestamp(0) + datetime.timedelta(seconds=epoch)).astimezone(datetime.timezone.utc))
	except:
		if len(str(datetime.datetime.now().astimezone()).split("+")) == 2:
			_dh =int(str(datetime.datetime.now().astimezone()).split("+")[1].split(":")[0])
		elif len(str(datetime.datetime.now().astimezone()).split("-")) == 4:
			_dh =int("-" + str(datetime.datetime.now().astimezone()).split("-")[3].split(":")[0])

		_td = datetime.timedelta(hours=_dh)
		_ltz = datetime.timezone(_td)
		_lt = (datetime.datetime.fromtimestamp(0) + datetime.timedelta(seconds=epoch))
		_utc = str(datetime.datetime(_lt.year, _lt.month, _lt.day, _lt.hour, _lt.minute, _lt.second, tzinfo=_ltz).astimezone(datetime.timezone.utc))

	return _utc

def conv_format_to_str(di_format):

	_s = "S_DINODE_FMT_UNKNOWN"
	if di_format == xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
		_s = "XFS_DINODE_FMT_LOCAL"
	elif di_format == xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
		_s = "XFS_DINODE_FMT_EXTENTS"
	elif di_format == xfs_dinode_fmt.XFS_DINODE_FMT_BTREE:
		_s = "XFS_DINODE_FMT_BTREE"
	elif di_format == xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
		_s = "XFS_DINODE_FMT_EXTENTS"
	elif di_format == xfs_dinode_fmt.XFS_DINODE_FMT_BTREE:
		_s = "XFS_DINODE_FMT_BTREE"
	elif di_format == xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
		_s = "XFS_DINODE_FMT_LOCAL"
	elif di_format == xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
		_s = "XFS_DINODE_FMT_EXTENTS"
	elif di_format == xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
		_s = "XFS_DINODE_FMT_LOCAL"
	elif di_format == xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
		_s = "XFS_DINODE_FMT_EXTENTS"
	elif di_format == xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
		_s = "XFS_DINODE_FMT_LOCAL"
	elif di_format == xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
		_s = "XFS_DINODE_FMT_EXTENTS"
	elif di_format == xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
		_s = "XFS_DINODE_FMT_LOCAL"
	elif di_format == xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
		_s = "XFS_DINODE_FMT_EXTENTS"
	elif di_format == xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
		_s = "XFS_DINODE_FMT_LOCAL"
	elif di_format == xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
		_s = "XFS_DINODE_FMT_EXTENTS"

	return _s

def conv_type_to_str(s_fmt):

	_s = "S_DELETED"
	if s_fmt == S_IFIFO:
		_s = "S_IFIFO"
	elif s_fmt == S_IFCHR:
		_s = "S_IFCHR"
	elif s_fmt == S_IFIFO:
		_s = "S_IFIFO"
	elif s_fmt == S_IFCHR:
		_s = "S_IFCHR"
	elif s_fmt == S_IFDIR:
		_s = "S_IFDIR"
	elif s_fmt == S_IFBLK:
		_s = "S_IFBLK"
	elif s_fmt == S_IFREG:
		_s = "S_IFREG"
	elif s_fmt == S_IFLNK:
		_s = "S_IFLNK"
	elif s_fmt == S_IFSOCK:
		_s = "S_IFSOCK"
	elif s_fmt == S_ISVTX:
		_s = "S_ISVTX"

	return _s
