from ctypes import *
import sys
import struct
import copy
from .misc import *
from .inode_rec import *

class XFS:

	def _has_ftype(self, inode_num):

		if inode_num == None:
			_ag_no = 0
		else:
			_ag_no = inode_num >> (self.superblocks[0][0].sb_agblklog + self.superblocks[0][0].sb_inopblog)
			if _ag_no > (len(self.superblocks) -1):
				_ag_no = 0

		_version = XFS_SB_VERSION_NUM(self.superblocks[_ag_no][0].sb_versionnum)
		_incompat = cpu_to_be32(self.superblocks[_ag_no][0].sb_features_incompat)
		_features2 = cpu_to_be32(self.superblocks[_ag_no][0].sb_features2)

		if (_version == XFS_SB_VERSION_5) and (_incompat & XFS_SB_FEAT_INCOMPAT_FTYPE) != 0:
			return True

		if (cpu_to_be16(self.superblocks[_ag_no][0].sb_versionnum) & XFS_SB_VERSION_MOREBITSBIT) and \
			(_features2 & XFS_SB_VERSION2_FTYPE):
			return True

		return False

	def _put_header(self):

		if self.first_inode_number == None:
			return

		if self.deleted:
			print("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" \
					% \
					("inode", "name", "mode", "uid", "gid", "size", \
					"atime", "mtime", "ctime", "crtime", "xfs_dir3_ft", \
					"di_mode_ft", "parent_inode", "path", "is_deleted"), file = self.out_fd)
		else:
			print("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" \
					% \
					("inode", "name", "mode", "uid", "gid", "size", \
					"atime", "mtime", "ctime", "crtime", "xfs_dir3_ft", \
					"di_mode_ft", "parent_inode", "path"), file = self.out_fd)

	def _put_inode_rec(self, inode_rec):

		if inode_rec.inode_core != None:
			_data_fork_type = get_type(inode_rec.inode_core.di_mode)
		
			if xfs_dinode_has_bigtime(inode_rec.inode_core.di_version, inode_rec.inode_core.di_flags2):
				_atime = timestamp_to_str(inode_rec.inode_core.di_atime)
				_mtime = timestamp_to_str(inode_rec.inode_core.di_mtime)
				_ctime = timestamp_to_str(inode_rec.inode_core.di_ctime)
				_crtime = timestamp_to_str(inode_rec.inode_core.di_crtime)
			else:
				_atime = legacy_timestamp_to_str(inode_rec.inode_core.di_atime)
				_mtime = legacy_timestamp_to_str(inode_rec.inode_core.di_mtime)
				_ctime = legacy_timestamp_to_str(inode_rec.inode_core.di_ctime)
				_crtime = legacy_timestamp_to_str(inode_rec.inode_core.di_crtime)
			_inode_num = inode_rec.inode_num
			_di_mode = cpu_to_be16(inode_rec.inode_core.di_mode)
			_di_uid = cpu_to_be32(inode_rec.inode_core.di_uid)
			_di_gid = cpu_to_be32(inode_rec.inode_core.di_gid)
			_di_size = cpu_to_be64(inode_rec.inode_core.di_size)
			
		else:
			_inode_num = inode_rec.inode_num
			_data_fork_type = 0
			_atime = "N/A"
			_mtime = "N/A"
			_ctime = "N/A"
			_crtime = "N/A"
			_di_mode = -1
			_di_uid = -1
			_di_gid = -1
			_di_size = -1

		if self.deleted:
			print("%d,%s,%o,%d,%d,%d,%s,%s,%s,%s,%s,%s,%d,%s,%s" \
					% \
					(_inode_num,\
					inode_rec.name,\
					_di_mode,\
					_di_uid,\
					_di_gid,\
					_di_size,\
					_atime,\
					_mtime,\
					_ctime,\
					_crtime,\
					inode_rec.ftype,\
					conv_type_to_str(_data_fork_type),\
					inode_rec.parent_inode_num, \
					inode_rec.parent_path, \
					str(inode_rec.is_deleted)), file = self.out_fd)
		else:
			print("%d,%s,%o,%d,%d,%d,%s,%s,%s,%s,%s,%s,%d,%s" \
					% \
					(_inode_num,\
					inode_rec.name,\
					_di_mode,\
					_di_uid,\
					_di_gid,\
					_di_size,\
					_atime,\
					_mtime,\
					_ctime,\
					_crtime,\
					inode_rec.ftype,\
					conv_type_to_str(_data_fork_type),\
					inode_rec.parent_inode_num, \
					inode_rec.parent_path), file = self.out_fd)

	def _get_inode_core(self, _inumber):

		if _inumber == -1:
			return (None, None)
		_o = self._get_inode_offset(_inumber)
		if _o == None:
			return (None, None)
		self.in_fd.seek(_o)
		_t = self.in_fd.read(sizeof(xfs_dinode))
		inode_core = New(_t, xfs_dinode)
		if cpu_to_be16(inode_core.di_magic) == XFS_DINODE_MAGIC:
			_inode_core = copy.deepcopy(inode_core)
			return (_o, _inode_core)
		else:
			return (None, None)

	def _get_ag_no_from_inode(self, inode_core):

		if inode_core.di_version != 0x3:
			return 0
		
		_di_ino = cpu_to_be64(inode_core.di_ino)
		_ag_no = _di_ino >> (self.superblocks[0][0].sb_agblklog + self.superblocks[0][0].sb_inopblog)

		return _ag_no

	def _set_leaf_dir(self, _data_fork_offset, inode_core, parent_inumber = -9, parent_path = ""):

		self.in_fd.seek(_data_fork_offset)
		_t = self.in_fd.read(sizeof(xfs_bmbt_rec))
		_bmbt_rec = New(_t, xfs_bmbt_rec)
		_bmbt_irec = copy.deepcopy(unpack_bmbt_rec(_bmbt_rec))
		_ag_no = self._get_ag_no_from_inode(inode_core)
		_size = _bmbt_irec.br_blockcount * cpu_to_be32(self.superblocks[_ag_no][0].sb_blocksize)
	
		_ag_no = _bmbt_irec.br_startblock >> self.superblocks[0][0].sb_agblklog
		_rel_mask = (1 << self.superblocks[0][0].sb_agblklog) -1
		_rel_block = _bmbt_irec.br_startblock & _rel_mask
		_sb_blocksize = cpu_to_be32(self.superblocks[_ag_no][0].sb_blocksize)
		_is_sb_version_5 = False
		if XFS_SB_VERSION_NUM(self.superblocks[_ag_no][0].sb_versionnum) == XFS_SB_VERSION_5:
			_is_sb_version_5 = True

		_o = (_ag_no * cpu_to_be32(self.superblocks[_ag_no][0].sb_agblocks) + _rel_block) * cpu_to_be32(self.superblocks[_ag_no][0].sb_blocksize)
		self.in_fd.seek(_o)
		if _is_sb_version_5:
			_t = self.in_fd.read(sizeof(xfs_dir3_blk_hdr))
			_dir3_blk_hdr = copy.deepcopy(New(_t, xfs_dir3_blk_hdr))
			if cpu_to_be32(_dir3_blk_hdr.magic) != XFS_DIR3_BLOCK_MAGIC and \
				cpu_to_be32(_dir3_blk_hdr.magic) != XFS_DIR3_DATA_MAGIC:
				return
		else:
			_t = self.in_fd.read(sizeof(xfs_dir2_data_hdr))
			_dir2_data_hdr = copy.deepcopy(New(_t, xfs_dir2_data_hdr))
			if cpu_to_be32(_dir2_data_hdr.magic) != XFS_DIR2_BLOCK_MAGIC and \
				cpu_to_be32(_dir2_data_hdr.magic) != XFS_DIR2_DATA_MAGIC:
				return

		for _b in range(_bmbt_irec.br_blockcount):
			_o_in_block = _b * _sb_blocksize
			_l = (_b + 1 ) * _sb_blocksize
			self.in_fd.seek(_o + _o_in_block)
			if _is_sb_version_5:
				_o_in_block += sizeof(xfs_dir3_data_hdr)
				_t = self.in_fd.read(sizeof(xfs_dir3_data_hdr))
				_data_hdr = copy.deepcopy(New(_t, xfs_dir3_data_hdr))
			else:
				_o_in_block += sizeof(xfs_dir2_data_hdr)
				_t = self.in_fd.read(sizeof(xfs_dir2_data_hdr))
				_data_hdr = copy.deepcopy(New(_t, xfs_dir2_data_hdr))
			while _o_in_block < _l:
				_o_in_block = self._parse_xfs_dir2_data(_o, _o_in_block, parent_inumber, parent_path)

	def _parse_xfs_dir2_data(self, offset, offset_in_block, parent_inumber, parent_path):
	
		_o = offset
		_o_in_block = offset_in_block

		_o_to_dir2_data_union = _o + _o_in_block
		self.in_fd.seek(_o_to_dir2_data_union)
		_t = self.in_fd.read(sizeof(xfs_dir2_data_union))
		_xfs_dir2_data_union = copy.deepcopy(New(_t, xfs_dir2_data_union))
		if (not self.deleted) and (cpu_to_be16(_xfs_dir2_data_union.unused.freetag) == 0xffff):
			_o_in_block += cpu_to_be16(_xfs_dir2_data_union.unused.length)
		else:
			_d = False
			if cpu_to_be16(_xfs_dir2_data_union.unused.freetag) == 0xffff:
				_d = True
				if (self.last_inode_number & 0x00000000ffffffff) == self.last_inode_number:
					_inumber = cpu_to_be64(_xfs_dir2_data_union.entry.inumber) & 0x00000000ffffffff
				else:
					_inumber = -1
				_free_len = cpu_to_be64(_xfs_dir2_data_union.entry.inumber) & 0x0000ffff00000000
				_free_len = _free_len >> 32
				_o_in_block_back = _o_in_block + _free_len
			else:
				_inumber = cpu_to_be64(_xfs_dir2_data_union.entry.inumber)

			_namelen = _xfs_dir2_data_union.entry.namelen
			_o_in_block += sizeof(c_uint64) + sizeof(c_uint8)
			_o_to_name = _o + _o_in_block
			self.in_fd.seek(_o_to_name)
			try:
				_name = self.in_fd.read(_namelen).decode('utf-8', errors='ignore').replace('\x00','')
			except Exception as e:
				_name =""
			_o_in_block += _namelen
			_ftype = 0
			if self._has_ftype(_inumber):
				_ftype, = struct.unpack(">B", self.in_fd.read(sizeof(c_uint8)))
				_o_in_block += sizeof(c_uint8)
			if _d == False:
				_o_in_block += sizeof(xfs_dir2_data_off)
				_o_in_block = roundup(_o_in_block, sizeof(c_uint64))
			else:
				_o_in_block = _o_in_block_back
				
			(_offset, _inode_core) = self._get_inode_core(_inumber)
			if (_name != ".") and (_name != "..") and (_offset != None) and (_d == False):
				inode_rec = InodeRec()
				inode_rec.parent_inode_num =  parent_inumber
				inode_rec.inode_core = _inode_core
				inode_rec.inode_num = _inumber
				inode_rec.name = _name
				inode_rec.parent_path = parent_path
				if not any(_t.value == _ftype for _t in xfs_dir3_ft):
					_ftype = 0
				inode_rec.ftype = xfs_dir3_ft(_ftype).name
				if parent_path == "/":
					_cur_path = parent_path + str(_name)
				else:
					_cur_path = parent_path + "/" + str(_name)
				inode_rec.is_deleted = False
				self._put_inode_rec(copy.deepcopy(inode_rec))
				self._load_inode_detail(_offset, _inode_core, _inumber, _cur_path)
			elif (_offset == None) or (_d == True):
				inode_rec = InodeRec()
				inode_rec.parent_inode_num =  parent_inumber
				inode_rec.inode_core = _inode_core
				if _offset != None:
					inode_rec.inode_num = _inumber
				else:
					inode_rec.inode_num = -1
				inode_rec.name = _name
				inode_rec.parent_path = parent_path
				if not any(_t.value == _ftype for _t in xfs_dir3_ft):
					_ftype = 0
				inode_rec.ftype = xfs_dir3_ft(_ftype).name
				if parent_path == "/":
					_cur_path = parent_path + str(_name)
				else:
					_cur_path = parent_path + "/" + str(_name)
				inode_rec.is_deleted = True
				self._put_inode_rec(copy.deepcopy(inode_rec))

		return _o_in_block

	def _set_block_dir(self, _data_fork_offset, inode_core, parent_inumber = -9, parent_path = ""):

		_nextents = cpu_to_be32(inode_core.di_nextents)
		self.in_fd.seek(_data_fork_offset)
		if _nextents == 0:
			pass
		elif _nextents == 1:
			_t = self.in_fd.read(sizeof(xfs_bmbt_rec))
			_bmbt_rec = New(_t, xfs_bmbt_rec)
			_bmbt_irec = copy.deepcopy(unpack_bmbt_rec(_bmbt_rec))
			_ag_no = self._get_ag_no_from_inode(inode_core)
			_size = _bmbt_irec.br_blockcount * cpu_to_be32(self.superblocks[_ag_no][0].sb_blocksize)
			_is_sb_version_5 = False
			if XFS_SB_VERSION_NUM(self.superblocks[_ag_no][0].sb_versionnum) == XFS_SB_VERSION_5:
				_is_sb_version_5 = True
			_ag_no = _bmbt_irec.br_startblock >> self.superblocks[0][0].sb_agblklog
			_rel_mask = (1 << self.superblocks[0][0].sb_agblklog) -1
			_rel_block = _bmbt_irec.br_startblock & _rel_mask
			_o = (_ag_no * cpu_to_be32(self.superblocks[_ag_no][0].sb_agblocks) + _rel_block) * cpu_to_be32(self.superblocks[_ag_no][0].sb_blocksize)
			_o_in_block = 0
			self.in_fd.seek(_o)
			if _is_sb_version_5:
				_o_in_block += sizeof(xfs_dir3_data_hdr)
				_t = self.in_fd.read(sizeof(xfs_dir3_data_hdr))
				_data_hdr = copy.deepcopy(New(_t, xfs_dir3_data_hdr))
			else:
				_o_in_block += sizeof(xfs_dir2_data_hdr)
				_t = self.in_fd.read(sizeof(xfs_dir2_data_hdr))
				_data_hdr = copy.deepcopy(New(_t, xfs_dir2_data_hdr))

			_o_to_dir2_block_tail = _o + _size - sizeof(xfs_dir2_block_tail)
			self.in_fd.seek(_o_to_dir2_block_tail)
			_t = self.in_fd.read(sizeof(xfs_dir2_block_tail))
			_dir2_block_tail = copy.deepcopy(New(_t, xfs_dir2_block_tail))
			
			_o_to_dir2_leaf_entry_in_block = _size - sizeof(xfs_dir2_block_tail) - cpu_to_be32(_dir2_block_tail.count) * sizeof(xfs_dir2_leaf_entry)

			while _o_in_block < _o_to_dir2_leaf_entry_in_block:
				_o_in_block = self._parse_xfs_dir2_data(_o, _o_in_block, parent_inumber, parent_path)
		else:
			for _i in range(_nextents):
				self._set_leaf_dir(_data_fork_offset, inode_core, parent_inumber, parent_path)
				_data_fork_offset += sizeof(xfs_bmbt_rec)

	def _set_short_form_dir(self, _data_fork_offset, parent_inumber = -9, parent_path = ""):
		
		_t = self.in_fd.read(sizeof(xfs_dir2_sf_hdr))
		__dir2_sf_hdr = New(_t, xfs_dir2_sf_hdr)
		_dir2_sf_hdr = copy.deepcopy(__dir2_sf_hdr)
		if _dir2_sf_hdr.i8count > 0:
			_count = _dir2_sf_hdr.i8count
			_dir2_sf_entry_offset = _data_fork_offset + sizeof(c_uint8) + sizeof(c_uint8) + sizeof(xfs_dir2_ino8)
			_parent_inode_num = array_to_num(_dir2_sf_hdr.parent.i8)
		else:
			_count = _dir2_sf_hdr.count
			_dir2_sf_entry_offset = _data_fork_offset + sizeof(c_uint8) + sizeof(c_uint8) + sizeof(xfs_dir2_ino4)
			_parent_inode_num = array_to_num(_dir2_sf_hdr.parent.i4)
		_i = 0
		if parent_inumber != -9:
			_parent_inode_num = parent_inumber

		while True:
			if (not self.deleted) and (_i >= _count):
				break

			self.in_fd.seek(_dir2_sf_entry_offset)
			_t = self.in_fd.read(sizeof(xfs_dir2_sf_entry))
			dir2_sf_entry = New(_t, xfs_dir2_sf_entry)
			
			_namelen = dir2_sf_entry.namelen
			_dir2_sf_entry_offset += sizeof(c_uint8) + sizeof( xfs_dir2_sf_off)
			self.in_fd.seek(_dir2_sf_entry_offset)
			try:
				_name = self.in_fd.read(_namelen).decode('utf-8', errors='ignore').replace('\x00','')
			except Exception as e:
				_name = ""
			
			_dir2_sf_entry_offset += _namelen
			self.in_fd.seek(_dir2_sf_entry_offset)

			_ftype = 0
			if self._has_ftype(_parent_inode_num):
				_ftype, = struct.unpack(">B", self.in_fd.read(sizeof(c_uint8)))
				_dir2_sf_entry_offset += sizeof(c_uint8)
			
			if _dir2_sf_hdr.i8count > 0:
				_inumber_len = sizeof(xfs_dir2_ino8)
				_inumber, = struct.unpack(">Q", self.in_fd.read(_inumber_len))
			else:
				_inumber_len = sizeof(xfs_dir2_ino4)
				_inumber, = struct.unpack(">I", self.in_fd.read(_inumber_len))

			_dir2_sf_entry_offset += _inumber_len

			(_offset, _inode_core) = self._get_inode_core(_inumber)
			if _offset == None:
				break
			inode_rec = InodeRec()
			inode_rec.parent_inode_num = _parent_inode_num
			inode_rec.inode_core = _inode_core
			inode_rec.name = _name
			inode_rec.parent_path = parent_path
			inode_rec.inode_num = _inumber
			inode_rec.ftype = xfs_dir3_ft(_ftype).name
			if _i >= _count:
				inode_rec.is_deleted = True
			if parent_path == "/":
				_cur_path = parent_path + str(_name)
			else:
				_cur_path = parent_path + "/" + str(_name)
			self._put_inode_rec(copy.deepcopy(inode_rec))
			if not inode_rec.is_deleted:
				self._load_inode_detail(_offset, _inode_core, _inumber, _cur_path)
			_i += 1

	def _set_btree_dir(self, _data_fork_offset, inode_core, parent_inumber = -9, is_root = False, parent_path = ""):

		_bb_level = 0
		_bb_numrecs = 0
		_bmdr_block = None
		_o = _data_fork_offset
		self.in_fd.seek(_o)
		if is_root:
			_t = self.in_fd.read(sizeof(xfs_bmdr_block))
			_o += sizeof(xfs_bmdr_block)
			__bmdr_block = New(_t, xfs_bmdr_block)
			_bmdr_block = copy.deepcopy(__bmdr_block)

			_bb_level = cpu_to_be16(_bmdr_block.bb_level)
			_bb_numrecs = cpu_to_be16(_bmdr_block.bb_numrecs)

		else:
			_t = self.in_fd.read(sizeof(xfs_bmbt_block))
			_o += sizeof(xfs_bmbt_block)
			__bmbt_block = New(_t, xfs_bmbt_block)
			_bmbt_block = copy.deepcopy(__bmbt_block)
			
			if XFS_SB_VERSION_NUM(self.superblocks[0][0].sb_versionnum) != XFS_SB_VERSION_5:
				_o -= (sizeof(c_uint64) * 3 + sizeof(c_uint32) * 2 + sizeof(uuid))
				self.in_fd.seek(_o)

			_bb_level = cpu_to_be16(_bmbt_block.bb_level)
			_bb_numrecs = cpu_to_be16(_bmbt_block.bb_numrecs)

		_ag_no = self._get_ag_no_from_inode(inode_core)
		_dblocksize = XFS_DFORK_SIZE(inode_core.di_forkoff, \
					cpu_to_be16(self.superblocks[_ag_no][0].sb_inodesize), \
					inode_core.di_version, XFS_DATA_FORK)

		if _bb_level > 0:
			_maxrecs = xfs_bmdr_maxrecs(_dblocksize, False)
			_bmbt_ptrs = []
			_o += _maxrecs * sizeof(xfs_bmbt_key)
			self.in_fd.seek(_o)
			for _i in range(_bb_numrecs):
				_t = self.in_fd.read(sizeof(xfs_bmbt_ptr))
				_bmbt_ptr = New(_t, xfs_bmbt_ptr)
				_bmbt_ptrs.append(copy.deepcopy(_bmbt_ptr))
				_o += sizeof(xfs_bmbt_ptr)
			
			for _i in range(_bb_numrecs):
				_next_node_block = cpu_to_be64(_bmbt_ptrs[_i].value)
				_ag_no = _next_node_block >> self.superblocks[0][0].sb_agblklog
				_rel_mask = (1 << self.superblocks[_ag_no][0].sb_agblklog) -1
				_rel_block = _next_node_block & _rel_mask
				_o = (_ag_no * cpu_to_be32(self.superblocks[_ag_no][0].sb_agblocks) + _rel_block) * cpu_to_be32(self.superblocks[_ag_no][0].sb_blocksize)
				self._set_btree_dir(_o, inode_core, parent_inumber, False, parent_path)
		else:
			_data_fork_offset = _o
			for _i in range(_bb_numrecs):
				self._set_leaf_dir(_data_fork_offset,inode_core, parent_inumber, parent_path)
				_data_fork_offset += sizeof(xfs_bmbt_rec)

	def _load_inode_detail(self, offset, inode_core, parent_inumber = -9, parent_path = ""):

		_data_fork_offset = offset + inode_core.size()
		_data_fork_type = get_type(inode_core.di_mode)
		self.in_fd.seek(_data_fork_offset)
		if _data_fork_type == S_IFDIR:
			if inode_core.di_format == xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
				self._set_short_form_dir(_data_fork_offset, parent_inumber, parent_path)
				
			elif inode_core.di_format == xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
				self._set_block_dir(_data_fork_offset, inode_core, parent_inumber, parent_path)
				
			elif inode_core.di_format == xfs_dinode_fmt.XFS_DINODE_FMT_BTREE:
				self._set_btree_dir(_data_fork_offset, inode_core, parent_inumber, True, parent_path)
		else:
			pass

	def _get_inode_offset(self, inode):

		_ag_no = inode >> (self.superblocks[0][0].sb_agblklog + self.superblocks[0][0].sb_inopblog)
		if _ag_no > (len(self.superblocks) -1):
			return None

		_rel_mask = (1 << (self.superblocks[0][0].sb_agblklog + self.superblocks[0][0].sb_inopblog)) -1
		_rel_inode = inode & _rel_mask
		_rel_block = _rel_inode >> self.superblocks[0][0].sb_inopblog
		_rel_block_rem_mask = (1 << self.superblocks[0][0].sb_inopblog) -1
		_rel_offset = _rel_inode & _rel_block_rem_mask
		_o = _ag_no * cpu_to_be32(self.superblocks[_ag_no][0].sb_agblocks) * cpu_to_be32(self.superblocks[_ag_no][0].sb_blocksize) \
			+ _rel_block * cpu_to_be32(self.superblocks[_ag_no][0].sb_blocksize) \
			+ _rel_offset * cpu_to_be16(self.superblocks[_ag_no][0].sb_inodesize)

		return _o

	def _set_first_inode(self, inode, _inode_core):

		inode_rec = InodeRec()
		inode_rec.parent_inode_num = -9
		inode_rec.inode_core = _inode_core
		inode_rec.name = "/"
		inode_rec.parent_path = ""
		inode_rec.inode_num = inode
		inode_rec.ftype = ""
		self._put_inode_rec(copy.deepcopy(inode_rec))
	
	def _load_inode(self, inode):

		_o = self._get_inode_offset(inode)
		if _o == None:
			return

		self.in_fd.seek(_o)
		_t = self.in_fd.read(sizeof(xfs_dinode))
		inode_core = New(_t, xfs_dinode)
		if cpu_to_be16(inode_core.di_magic) == XFS_DINODE_MAGIC:
			_inode_core = copy.deepcopy(inode_core)
			self._set_first_inode(inode, _inode_core)
			self._load_inode_detail(_o, _inode_core, inode, "/")

	def _load_inodes(self):

		if self.first_inode_number:
			_inode = self.first_inode_number
		else:
			return

		self._load_inode(_inode)
			
	def _set_inode_range(self):

		if len(self.superblocks) == 0:
			return

		self.first_inode_number = cpu_to_be64(self.superblocks[0][0].sb_rootino)
		_max_inum = 0
		for _i in range(len(self.superblocks) - 1):
			_max_inum += 1 << self.superblocks[_i][0].sb_agblklog + self.superblocks[_i][0].sb_inopblog

		self.last_inode_number = _max_inum \
								+ cpu_to_be32(self.ag_inode_b_plus_tree_info[len(self.ag_inode_b_plus_tree_info) -  1][1].agi_length) \
								* cpu_to_be16(self.superblocks[len(self.superblocks) - 1][0].sb_inopblock) \
								- 1

	def _set_inode_b_plus_tree_info(self):

		self.ag_inode_b_plus_tree_info = []
		_r = []
		_o = 0
		for _sb in self.superblocks:
			_o = _sb[1]
			_o += cpu_to_be16(_sb[0].sb_sectsize) * 2
			self.in_fd.seek(_o)
			_t = self.in_fd.read(sizeof(xfs_agi))
			agi = New(_t, xfs_agi)
			if cpu_to_be32(agi.agi_magicnum) == XFS_AGI_MAGIC:
				self.ag_inode_b_plus_tree_info.append((cpu_to_be32(agi.agi_seqno), copy.deepcopy(agi)))

	def _set_superblocks(self):

		self.superblocks = []
		_p = []
		_o = 0
		while True:
			self.in_fd.seek(_o)
			_t = self.in_fd.read(sizeof(xfs_sb))
			sb = New(_t, xfs_sb)
			if cpu_to_be32(sb.sb_magicnum) != XFS_SB_MAGIC:
				if len(self.superblocks) == 0:
					print("target is not XFS", file=sys.stderr)
					self.first_inode_number = None
				break

			_bs = cpu_to_be32(sb.sb_blocksize)

			self.superblocks.append((copy.deepcopy(sb), _o, _bs))
			_o += cpu_to_be32(sb.sb_blocksize) * cpu_to_be32(sb.sb_agblocks)

	def search_inodes(self):

		self._set_inode_b_plus_tree_info()
		self._set_inode_range()
		self._put_header()
		self._load_inodes()

	def __del__(self):

		self.in_fd.close()
		self.out_fd.close()


	def __init__(self, inf, outf, deleted):

		try:
			in_fd = open(inf, "rb")
		except:
			print("cannot open source dump file.", file=sys.stderr)
			sys.exit(-1)

		try:
			out_fd = open(outf, "w", encoding="utf-8")
		except:
			print("cannot open target file.", file=sys.stderr)
			sys.exit(-1)

		self.in_fd = in_fd
		self.out_fd = out_fd
		self.deleted = deleted
		self._set_superblocks()
