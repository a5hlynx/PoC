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
XFS_SB_MAGIC = 0x58465342
XFS_AGI_MAGIC = 0x58414749
XFS_DINODE_MAGIC = 0x494e

XFS_DIFLAG2_BIGTIME_BIT = 3
XFS_DIFLAG2_NREXT64_BIT = 4

XFS_DIFLAG2_BIGTIME = (1 << XFS_DIFLAG2_BIGTIME_BIT)
XFS_DIFLAG2_NREXT64 = (1 << XFS_DIFLAG2_NREXT64_BIT)

NSEC_PER_SEC = 1000000000
S32_MIN = -2147483648
XFS_BIGTIME_EPOCH_OFFSET = -S32_MIN

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

XFS_SB_VERSION_5 = 5
XFS_SB_VERSION_NUMBITS =  0x000f
XFS_SB_VERSION_MOREBITSBIT = 0x8000

XFS_SB_VERSION2_FTYPE = 0x00000200

BMBT_EXNTFLAG_BITLEN = 1

XFS_SB_FEAT_INCOMPAT_FTYPE = (1 << 0)

XFS_DIR2_BLOCK_MAGIC = 0x58443242
XFS_DIR2_DATA_MAGIC = 0x58443244
XFS_DIR3_BLOCK_MAGIC = 0x58444233
XFS_DIR3_DATA_MAGIC = 0x58444433


XFS_DATA_FORK = 0

XFS_DIR2_DATA_FD_COUNT = 3

xfs_bmbt_ptr = c_uint64
xfs_bmdr_ptr = c_uint64

xfs_rfsblock = c_uint64
xfs_rtblock = c_uint64
xfs_fsblock = c_uint64
xfs_agblock = c_uint32
xfs_agnumber = c_uint32
xfs_extlen = c_uint32
xfs_lsn = c_int64
xfs_aextnum = c_int16
xfs_fsize = c_int64
xfs_fileoff = c_uint64
xfs_filblks = c_uint64

xfs_ino = c_uint64
xfs_extnum = c_uint32

xfs_dir2_data_off = c_uint16
xfs_dir2_ino8 = c_uint8 * 8
xfs_dir2_ino4 = c_uint8 * 4

def XFS_SB_VERSION_NUM(sb_versionnum):

	return cpu_to_be16(sb_versionnum) & XFS_SB_VERSION_NUMBITS

def xfs_dinode_size(version):

	_size = sizeof(xfs_dinode)
	if version != 0x3:
		_size -= sizeof(c_uint64) * 4 + sizeof(c_uint32) * 2 + \
				sizeof(uuid_t) + sizeof(xfs_timestamp) + \
				sizeof(c_uint8) * 12

	return _size

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

def _from_cpu(val, bytes):

	_v = 0
	if sys.byteorder == "little":
		_val = val.to_bytes(bytes,byteorder=sys.byteorder)
		for i in range(len(_val)):
			_v = _v + (_val[len(_val)-1-i] << 8*i)
	else:
		_v = val

	return _v

def cpu_to_be16(val):

	if val < 0:
		val = val & 0xffff

	return _from_cpu(val, 2)

def cpu_to_be32(val):

	if val < 0:
		val = val & 0xffffffff

	return _from_cpu(val, 4)

def cpu_to_be64(val):

	if val < 0:
		val = val & 0xffffffffffffffff
	return _from_cpu(val, 8)

def conv_be64(b):

	_val = 0
	for i in range(8):
		_val = _val + (b[7-i]<<i*8)

	return _val

def get_type(mode):
	
	_m = cpu_to_be16(mode)& S_IFMT
	
	return _m

def conv_type_to_str(s_fmt):

	_s = "S_UNKNOWN"
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

def xfs_mask64lo(n):

	return ((1 &  0xffffffffffffffff) << (n)) - 1

def unpack_bmbt_rec(bmbt_rec):

	l0 = cpu_to_be64(bmbt_rec.l0)
	l1 = cpu_to_be64(bmbt_rec.l1)
	bmbt_irec = xfs_bmbt_irec()
	bmbt_irec.br_startoff = (l0 & xfs_mask64lo(64 - BMBT_EXNTFLAG_BITLEN)) >> 9
	bmbt_irec.br_startblock = ((l0 & xfs_mask64lo(9)) << 43) | (l1 >> 21)
	bmbt_irec.br_blockcount = l1 & xfs_mask64lo(21)

	if l0 >> (64 - BMBT_EXNTFLAG_BITLEN):
		bmbt_irec.br_state = xfs_exntst.XFS_EXT_UNWRITTEN
	else:
		bmbt_irec.br_state = xfs_exntst.XFS_EXT_NORM

	return bmbt_irec

def roundup(x, y):

	return ( ( ((x)+((y) - 1)) // (y)) * (y) )

def xfs_bmdr_maxrecs(blocklen, is_leaf):

	blocklen -= sizeof(xfs_bmdr_block)

	if is_leaf:
		return blocklen // sizeof(xfs_bmdr_rec)

	return blocklen // (sizeof(xfs_bmdr_key) + sizeof(xfs_bmdr_ptr))


def New(src, target):

	_c = cast(src, POINTER(target)).contents
	return _c

def get_uuid(uuid):

	_uuid = ""
	for _u in uuid.u_bits:
		_uuid = _uuid + "{0:x}".format(_u)

	return _uuid

def array_to_num(arr):

	_num = 0
	for _i in range(len(arr)):
		_num += arr[_i] << (len(arr)-1-_i)

	return _num

def xfs_dinode_has_bigtime(_version, _flags2):

	if _version < 3:
		return False

	return _flags2 & cpu_to_be64(XFS_DIFLAG2_BIGTIME)

def timestamp_to_str(_time):

	_time = (cpu_to_be32(_time.t_sec) << 32) + cpu_to_be32(_time.t_nsec)
	_epoch = _time // NSEC_PER_SEC
	_nano = _time % NSEC_PER_SEC
	_epoch = _epoch - XFS_BIGTIME_EPOCH_OFFSET

	_t = str((datetime.datetime.fromtimestamp(0) + datetime.timedelta(seconds=_epoch)).astimezone(datetime.timezone.utc))
	_timestamp = _t.split("+")[0] + "." + str(cpu_to_be32(_nano))

	return _timestamp

def legacy_timestamp_to_str(_time):

	_t = str((datetime.datetime.fromtimestamp(0) + datetime.timedelta(seconds=cpu_to_be32(_time.t_sec))).astimezone(datetime.timezone.utc))
	_timestamp = _t.split("+")[0] + "." + str(cpu_to_be32(_time.t_nsec))

	return _timestamp

class xfs_exntst(IntEnum):
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

class uuid(Structure):
	_fields_ = [
		("u_bits", c_ubyte * 16)
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
		("di_crc", c_uint32),			# __le32
		("di_changecount", c_uint64),
		("di_lsn", c_uint64),
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
			return sizeof(xfs_dinode) - (sizeof(c_uint64) * 4 + sizeof(c_uint32) * 2 + sizeof(uuid) + sizeof(xfs_timestamp) + sizeof(c_uint8) * 12)

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
		("sb_meta_uuid", uuid)
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

class xfs_dir2_data_union(Union):
	_fields_ = [
		("entry", xfs_dir2_data_entry),
		("unused", xfs_dir2_data_unused)
	]
