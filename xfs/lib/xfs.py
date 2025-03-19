# references
# https://github.com/isciurus/sleuthkit
# https://web.git.kernel.org/pub/scm/fs/xfs/xfsprogs-dev.git

from ctypes import *
import sys
import struct
import copy
from .misc import *
from .inode_rec import *
import os

q="\"\""

class XFS:

	def _put_meta_header(self):

		if self.first_inode_number == None:
			return
		if self.deleted:
			print("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" \
					% \
					("inode", "name", "mode", "uid", "gid", "size", \
					"atime", "mtime", "ctime", "crtime", "xfs_dir3_ft", \
					"di_mode_ft", "parent_inode", "path", "sl_target", "attrs", "is_deleted"), file = self.out_fd)
		else:
			print("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" \
					% \
					("inode", "name", "mode", "uid", "gid", "size", \
					"atime", "mtime", "ctime", "crtime", "xfs_dir3_ft", \
					"di_mode_ft", "parent_inode", "path", "sl_target", "attrs"), file = self.out_fd)

	def _put_inode_rec(self, inode_rec):

		if inode_rec.inode_num < 0:
			return

		_data_fork_type_str = "-"
		_atime = "-"
		_mtime = "-"
		_ctime = "-"
		_crtime = "-"
		_di_mode = -1
		_di_uid = -1
		_di_gid = -1
		_di_size = -1
		_ftype_str = "-"
		_parent_inode_num = inode_rec.parent_inode_num
		if inode_rec.parent_inode_num < 0:
			_parent_inode_num = 0

		if inode_rec.inode_core != None:
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
			_di_mode = cpu_to_be16(inode_rec.inode_core.di_mode)
			_di_uid = cpu_to_be32(inode_rec.inode_core.di_uid)
			_di_gid = cpu_to_be32(inode_rec.inode_core.di_gid)
			_di_size = cpu_to_be64(inode_rec.inode_core.di_size)
			_data_fork_type_str = conv_type_to_str(get_type(inode_rec.inode_core.di_mode))
			if inode_rec.inode_core.di_version != 0x03:
				_crtime = "-"
			if xfs_has_ftype(self._m_features):
				_ftype_str = inode_rec.ftype

		if self.deleted:
			print("0x%x(%d),\"%s\",0o%o,%d,%d,%d,%s,%s,%s,%s,%s,%s,0x%x(%d),\"%s\",\"%s\",%s,,\"%s\"" \
					% \
					(inode_rec.inode_num,inode_rec.inode_num,\
					inode_rec.name,\
					_di_mode,\
					_di_uid,\
					_di_gid,\
					_di_size,\
					_atime,\
					_mtime,\
					_ctime,\
					_crtime,\
					_ftype_str,\
					_data_fork_type_str,\
					_parent_inode_num,_parent_inode_num,\
					inode_rec.parent_path,\
					inode_rec.sl_target,\
					str(inode_rec.attrs),\
					str(inode_rec.is_deleted)), file = self.out_fd)
		else:
			print("0x%x(%d),\"%s\",0o%o,%d,%d,%d,%s,%s,%s,%s,%s,%s,0x%x(%d),\"%s\",\"%s\",\"%s\"" \
					% \
					(inode_rec.inode_num,inode_rec.inode_num,\
					inode_rec.name,\
					_di_mode,\
					_di_uid,\
					_di_gid,\
					_di_size,\
					_atime,\
					_mtime,\
					_ctime,\
					_crtime,\
					_ftype_str,\
					_data_fork_type_str,\
					_parent_inode_num,_parent_inode_num,\
					inode_rec.parent_path,\
					inode_rec.sl_target,\
					str(inode_rec.attrs)), file = self.out_fd)

	def _get_inode_core(self, inumber):

		if inumber == -1:
			return None, None
		_o = self._get_inode_offset(inumber)
		if _o == None:
			return None, None
		self.in_fd.seek(_o)
		_ptr = self.in_fd.read(sizeof(xfs_dinode))
		_dinode = New(_ptr, xfs_dinode)
		if cpu_to_be16(_dinode.di_magic) == XFS_DINODE_MAGIC:
			_inode_core = copy.deepcopy(_dinode)
			return _o, _inode_core
		else:
			return None, None

	def _get_ag_no_from_inode(self, inode_core, is_bigendian = True):

		if inode_core.di_version != 0x3:
			return 0
		if is_bigendian:
			_di_ino = cpu_to_be64(inode_core.di_ino)
		else:
			_di_ino = inode_core.di_ino
		_ag_no = _di_ino >> (self.superblocks[0][0].sb_agblklog + self.superblocks[0][0].sb_inopblog)

		return _ag_no

	def _set_leaf_dir(self, _data_fork_offset, inode_core, parent_inumber = -9, parent_path = ""):

		self.in_fd.seek(_data_fork_offset)
		_ptr = self.in_fd.read(sizeof(xfs_bmbt_rec))
		_bmbt_rec = New(_ptr, xfs_bmbt_rec)
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
			_ptr = self.in_fd.read(sizeof(xfs_dir3_blk_hdr))
			_dir3_blk_hdr = copy.deepcopy(New(_ptr, xfs_dir3_blk_hdr))
			if cpu_to_be32(_dir3_blk_hdr.magic) != XFS_DIR3_BLOCK_MAGIC and \
				cpu_to_be32(_dir3_blk_hdr.magic) != XFS_DIR3_DATA_MAGIC:
				return
		else:
			_ptr = self.in_fd.read(sizeof(xfs_dir2_data_hdr))
			_dir2_data_hdr = copy.deepcopy(New(_ptr, xfs_dir2_data_hdr))
			if cpu_to_be32(_dir2_data_hdr.magic) != XFS_DIR2_BLOCK_MAGIC and \
				cpu_to_be32(_dir2_data_hdr.magic) != XFS_DIR2_DATA_MAGIC:
				return

		for _b in range(_bmbt_irec.br_blockcount):
			_o_in_block = _b * _sb_blocksize
			_l = (_b + 1 ) * _sb_blocksize
			self.in_fd.seek(_o + _o_in_block)
			if _is_sb_version_5:
				_o_in_block += sizeof(xfs_dir3_data_hdr)
				_ptr = self.in_fd.read(sizeof(xfs_dir3_data_hdr))
				_data_hdr = copy.deepcopy(New(_ptr, xfs_dir3_data_hdr))
			else:
				_o_in_block += sizeof(xfs_dir2_data_hdr)
				_ptr = self.in_fd.read(sizeof(xfs_dir2_data_hdr))
				_data_hdr = copy.deepcopy(New(_ptr, xfs_dir2_data_hdr))
			while _o_in_block < _l:
				_o_in_block = self._parse_xfs_dir2_data(_o, _o_in_block, parent_inumber, parent_path)

	def _parse_xfs_dir2_data(self, offset, offset_in_block, parent_inumber, parent_path):

		_o = offset
		_o_in_block = offset_in_block
		_o_to_dir2_data_union = _o + _o_in_block
		self.in_fd.seek(_o_to_dir2_data_union)
		_ptr = self.in_fd.read(sizeof(xfs_dir2_data_union))
		_xfs_dir2_data_union = copy.deepcopy(New(_ptr, xfs_dir2_data_union))
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
			if xfs_has_ftype(self._m_features):
				_ftype, = struct.unpack(">B", self.in_fd.read(sizeof(c_uint8)))
				_o_in_block += sizeof(c_uint8)
			if _d == False:
				_o_in_block += sizeof(xfs_dir2_data_off)
				_o_in_block = roundup(_o_in_block, sizeof(c_uint64))
			else:
				_o_in_block = _o_in_block_back

			_offset, _inode_core = self._get_inode_core(_inumber)
			if (_name != ".") and (_name != "..") and (_offset != None) and (_d == False):
				inode_rec = InodeRec()
				inode_rec.parent_inode_num =  parent_inumber
				inode_rec.inode_core = _inode_core
				inode_rec.inode_num = _inumber
				inode_rec.name = _name
				inode_rec.parent_path = parent_path
				if not any(_ptr.value == _ftype for _ptr in xfs_dir3_ft):
					_ftype = 0
				inode_rec.ftype = xfs_dir3_ft(_ftype).name
				if parent_path == "/":
					_cur_path = parent_path + str(_name)
				else:
					_cur_path = parent_path + "/" + str(_name)
				inode_rec.is_deleted = False

				_dft = get_type(_inode_core.di_mode)
				if _dft == S_IFLNK:
					if _inode_core.di_format == xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
						inode_rec.sl_target = self._get_short_form_sl(_inumber, _inode_core)
					elif _inode_core.di_format == xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
						inode_rec.sl_target = self._get_block_sl(_inumber, _inode_core)
				if _inode_core.di_aformat == 1:
					inode_rec.attrs = self._get_short_form_attr(_inumber, _inode_core)
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
				if not any(_ptr.value == _ftype for _ptr in xfs_dir3_ft):
					_ftype = 0
				inode_rec.ftype = xfs_dir3_ft(_ftype).name
				if parent_path == "/":
					_cur_path = parent_path + str(_name)
				else:
					_cur_path = parent_path + "/" + str(_name)
				inode_rec.is_deleted = True

				if _inode_core != None:
					_dft = get_type(_inode_core.di_mode)
					if _dft == S_IFLNK:
						if _inode_core.di_format == xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
							inode_rec.sl_target = self._get_short_form_sl(_inumber, _inode_core)
						elif _inode_core.di_format == xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
							inode_rec.sl_target = self._get_block_sl(_inumber, _inode_core)
					if _inode_core.di_aformat == 1:
						inode_rec.attrs = self._get_short_form_attr(_inumber, _inode_core)

				self._put_inode_rec(copy.deepcopy(inode_rec))

		return _o_in_block

	def _set_block_dir(self, data_fork_offset, inode_core, parent_inumber = -9, parent_path = ""):

		_nextents = cpu_to_be32(inode_core.di_nextents)
		self.in_fd.seek(data_fork_offset)
		if _nextents == 0:
			pass
		elif _nextents == 1:
			_ptr = self.in_fd.read(sizeof(xfs_bmbt_rec))
			_bmbt_rec = New(_ptr, xfs_bmbt_rec)
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
				_ptr = self.in_fd.read(sizeof(xfs_dir3_data_hdr))
				_data_hdr = copy.deepcopy(New(_ptr, xfs_dir3_data_hdr))
			else:
				_o_in_block += sizeof(xfs_dir2_data_hdr)
				_ptr = self.in_fd.read(sizeof(xfs_dir2_data_hdr))
				_data_hdr = copy.deepcopy(New(_ptr, xfs_dir2_data_hdr))

			_o_to_dir2_block_tail = _o + _size - sizeof(xfs_dir2_block_tail)
			self.in_fd.seek(_o_to_dir2_block_tail)
			_ptr = self.in_fd.read(sizeof(xfs_dir2_block_tail))
			_dir2_block_tail = copy.deepcopy(New(_ptr, xfs_dir2_block_tail))

			_o_to_dir2_leaf_entry_in_block = _size - sizeof(xfs_dir2_block_tail) - cpu_to_be32(_dir2_block_tail.count) * sizeof(xfs_dir2_leaf_entry)
			while _o_in_block < _o_to_dir2_leaf_entry_in_block:
				_o_in_block = self._parse_xfs_dir2_data(_o, _o_in_block, parent_inumber, parent_path)
		else:
			for _i in range(_nextents):
				self._set_leaf_dir(data_fork_offset, inode_core, parent_inumber, parent_path)
				data_fork_offset += sizeof(xfs_bmbt_rec)

	def _set_short_form_dir(self, data_fork_offset, parent_inumber = -9, parent_path = ""):

		_ptr = self.in_fd.read(sizeof(xfs_dir2_sf_hdr))
		__dir2_sf_hdr = New(_ptr, xfs_dir2_sf_hdr)
		_dir2_sf_hdr = copy.deepcopy(__dir2_sf_hdr)
		if _dir2_sf_hdr.i8count > 0:
			_count = _dir2_sf_hdr.i8count
			_dir2_sf_entry_offset = data_fork_offset + sizeof(c_uint8) + sizeof(c_uint8) + sizeof(xfs_dir2_ino8)
			_parent_inode_num = array_to_num(_dir2_sf_hdr.parent.i8)
		else:
			_count = _dir2_sf_hdr.count
			_dir2_sf_entry_offset = data_fork_offset + sizeof(c_uint8) + sizeof(c_uint8) + sizeof(xfs_dir2_ino4)
			_parent_inode_num = array_to_num(_dir2_sf_hdr.parent.i4)
		_i = 0
		if parent_inumber != -9:
			_parent_inode_num = parent_inumber

		while True:
			if (not self.deleted) and (_i >= _count):
				break

			self.in_fd.seek(_dir2_sf_entry_offset)
			_ptr = self.in_fd.read(sizeof(xfs_dir2_sf_entry))
			dir2_sf_entry = New(_ptr, xfs_dir2_sf_entry)
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
			if xfs_has_ftype(self._m_features):
				_ftype, = struct.unpack(">B", self.in_fd.read(sizeof(c_uint8)))
				_dir2_sf_entry_offset += sizeof(c_uint8)

			if _dir2_sf_hdr.i8count > 0:
				_inumber_len = sizeof(xfs_dir2_ino8)
				_inumber, = struct.unpack(">Q", self.in_fd.read(_inumber_len))
			else:
				_inumber_len = sizeof(xfs_dir2_ino4)
				_inumber, = struct.unpack(">I", self.in_fd.read(_inumber_len))

			_dir2_sf_entry_offset += _inumber_len
			_offset, _inode_core = self._get_inode_core(_inumber)
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

			_dft = get_type(_inode_core.di_mode)
			if _dft == S_IFLNK:
				if _inode_core.di_format == xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
					inode_rec.sl_target = self._get_short_form_sl(_inumber, _inode_core)
				elif _inode_core.di_format == xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
					inode_rec.sl_target = self._get_block_sl(_inumber, _inode_core)
			if _inode_core.di_aformat == 1:
				inode_rec.attrs = self._get_short_form_attr(_inumber, _inode_core)

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
			_ptr = self.in_fd.read(sizeof(xfs_bmdr_block))
			_o += sizeof(xfs_bmdr_block)
			__bmdr_block = New(_ptr, xfs_bmdr_block)
			_bmdr_block = copy.deepcopy(__bmdr_block)
			_bb_level = cpu_to_be16(_bmdr_block.bb_level)
			_bb_numrecs = cpu_to_be16(_bmdr_block.bb_numrecs)
		else:
			_ptr = self.in_fd.read(sizeof(xfs_bmbt_block))
			_o += sizeof(xfs_bmbt_block)
			__bmbt_block = New(_ptr, xfs_bmbt_block)
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
				_ptr = self.in_fd.read(sizeof(xfs_bmbt_ptr))
				_bmbt_ptr = New(_ptr, xfs_bmbt_ptr)
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

	def _get_short_form_sl(self, i_num, inode_core):

		_org = self.in_fd.tell()
		_o = self._get_inode_offset(i_num) + inode_core.size()
		self.in_fd.seek(_o)
		_length = cpu_to_be64(inode_core.di_size)
		try:
			_name = self.in_fd.read(_length).decode('utf-8', errors='ignore').replace('\x00','')
		except Exception as e:
			_name = ""

		self.in_fd.seek(_org)

		return _name

	def _get_block_sl(self, i_num, inode_core):
		return ""

	def _get_short_form_attr(self, i_num, inode_core):

		_attrs = []
		_org = self.in_fd.tell()
		_o = self._get_inode_offset(i_num) + inode_core.size() + inode_core.di_forkoff * 8
		self.in_fd.seek(_o)
		_length = cpu_to_be64(inode_core.di_size)

		_ptr = self.in_fd.read(sizeof(xfs_attr_sf_hdr))
		_attr_sf_hdr = copy.deepcopy(New(_ptr, xfs_attr_sf_hdr))
		_totsize = cpu_to_be16(_attr_sf_hdr.totsize)
		_count = _attr_sf_hdr.count
		for _i in range(0, _count, 1):
			_o = self.in_fd.tell()
			_ptr = self.in_fd.read(sizeof(xfs_attr_sf_entry))
			_attr_sf_entry = copy.deepcopy(New(_ptr, xfs_attr_sf_entry))
			_namelen = _attr_sf_entry.namelen
			_valuelen = _attr_sf_entry.valuelen
			_flags = _attr_sf_entry.flags
			self.in_fd.seek(_o + xfs_attr_sf_entry.nameval.offset)
			_name = self.in_fd.read(_namelen).decode('utf-8', errors='ignore').replace('\x00','')
			try:
				_value = self.in_fd.read(_valuelen).decode('utf-8').replace('\x00','').replace('"','""')
			except:
				_value = "0x" + self.in_fd.read(_valuelen).hex()

			_flags_str = ""
			if _flags & XFS_ATTR_LOCAL:
				_flags_str = "XFS_ATTR_LOCAL"
			if _flags & XFS_ATTR_ROOT:
				if len(_flags_str) > 0:
					_flags_str = _flags_str + "|"
				_flags_str = _flags_str + "XFS_ATTR_ROOT"
			if _flags & XFS_ATTR_SECURE:
				if len(_flags_str) > 0:
					_flags_str = _flags_str + "|"
				_flags_str = _flags_str + "XFS_ATTR_SECURE"
			if _flags & XFS_ATTR_PARENT:
				if len(_flags_str) > 0:
					_flags_str = _flags_str + "|"
				_flags_str = _flags_str + "XFS_ATTR_PARENT"
			if _flags & XFS_ATTR_INCOMPLETE:
				if len(_flags_str) > 0:
					_flags_str = _flags_str + "|"
				_flags_str = _flags_str + "XFS_ATTR_INCOMPLETE"
			_attr = []
			_attr.append(_name)
			_attr.append(_value)
			_attr.append(_flags_str)
			_attrs.append(_attr)

		self.in_fd.seek(_org)
		
		return _attrs

	def _set_first_inode(self, inode, inode_core):

		inode_rec = InodeRec()
		inode_rec.parent_inode_num = -9
		inode_rec.inode_core = inode_core
		inode_rec.name = "/"
		inode_rec.parent_path = ""
		inode_rec.inode_num = inode
		inode_rec.ftype = ""
		_dft = get_type(inode_core.di_mode)
		if _dft == S_IFLNK:
			if inode_core.di_format == xfs_dinode_fmt.XFS_DINODE_FMT_LOCAL:
				inode_rec.sl_target = self._get_short_form_sl(inode, inode_core)
			elif inode_core.di_format == xfs_dinode_fmt.XFS_DINODE_FMT_EXTENTS:
				inode_rec.sl_target = self._get_block_sl(inode, inode_core)
		if inode_core.di_aformat == 1:
			inode_rec.attrs = self._get_short_form_attr(inode, inode_core)

		self._put_inode_rec(copy.deepcopy(inode_rec))

	def _load_inode(self, inode):

		_o = self._get_inode_offset(inode)
		if _o == None:
			return

		self.in_fd.seek(_o)
		_ptr = self.in_fd.read(sizeof(xfs_dinode))
		inode_core = New(_ptr, xfs_dinode)
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
			_ptr = self.in_fd.read(sizeof(xfs_agi))
			agi = New(_ptr, xfs_agi)
			if cpu_to_be32(agi.agi_magicnum) == XFS_AGI_MAGIC:
				self.ag_inode_b_plus_tree_info.append((cpu_to_be32(agi.agi_seqno), copy.deepcopy(agi)))

	def _set_superblocks(self):

		self.superblocks = []
		_p = []
		_o = 0
		while True:
			self.in_fd.seek(_o)
			_ptr = self.in_fd.read(sizeof(xfs_sb))
			sb = New(_ptr, xfs_sb)
			if cpu_to_be32(sb.sb_magicnum) != XFS_SB_MAGIC:
				if len(self.superblocks) == 0:
					print("target is not XFS", file=sys.stderr)
					sys.exit(-1)
				break

			_bs = cpu_to_be32(sb.sb_blocksize)
			self.superblocks.append((copy.deepcopy(sb), _o, _bs))
			_o += cpu_to_be32(sb.sb_blocksize) * cpu_to_be32(sb.sb_agblocks)

		_m_features = xfs_sb_version_to_features(self.superblocks[0][0])
		self._m_features = _m_features

	def _put_journal_header(self):

		print("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" \
				% \
				("tid", "item_no", "type", "affected", "inode", "name", "mode", \
				"uid", "gid", "size", "atime", "mtime", "ctime", "crtime", "xfs_dir3_ft", \
				"di_mode_ft", "parent_inode", "extra"), file = self.out_fd)

	def _get_inode_number(self, ag_no, agbno, isize):

		_inode = (ag_no << (self.superblocks[ag_no][0].sb_agblklog + self.superblocks[ag_no][0].sb_inopblog)) \
			+ (agbno << self.superblocks[ag_no][0].sb_inopblog) \
			+ isize // cpu_to_be16(self.superblocks[ag_no][0].sb_inodesize)
		return _inode

	def _xlog_buf_bbcount_valid(self, bbcount):
		return (bbcount > 0) and bbcount <= self._logBBsize

	def _round_mask(self, x, y):
		return y - 1

	def _round_down(self, x, y):
		return ((x) & ~self._round_mask(x, y))

	def _round_up(self, x, y):
		return ((((x)-1) | self._round_mask(x, y))+1)

	def _xlog_get_cycle(self, offset):

		self.in_fd.seek(offset)
		_ptr = self.in_fd.read(sizeof(xlog_rec_header))
		_rec_header = copy.deepcopy(New(_ptr, xlog_rec_header))
		if cpu_to_be32(_rec_header.h_magicno) == XLOG_HEADER_MAGIC:
			_cycle = cpu_to_be32(_rec_header.h_cycle)
		else:
			_cycle = cpu_to_be32(_rec_header.h_magicno)
		return _cycle

	def _xlog_bread_noalign(self, blk_no, nbblks):

		if not self._xlog_buf_bbcount_valid(nbblks):
			return -1, -1

		blk_no = self._round_down(blk_no, self._sectBBsize)
		nbblks = self._round_up(nbblks, self._sectBBsize)
		bytes = BBTOB(nbblks);
		_o = LIBXFS_BBTOOFF64(self._logBBstart + blk_no)

		return _o

	def _xlog_align(self, blk_no, nbblks, offset):
		__o = blk_no & (self._sectBBsize - 1)
		_o = BBTOB(__o)
		return offset + _o

	def _xlog_bread(self, blk_no, nbblks):
	
		_err = 0
		__o = self._xlog_bread_noalign(blk_no, nbblks)
		if _err < 0:
			_err = -9

		_o = self._xlog_align(blk_no, nbblks, __o)
		return _err, _o

	def _xlog_find_cycle_start(self, first_blk, last_blk, cycle):

		end_blk = last_blk
		mid_blk = BLK_AVG(first_blk, end_blk)
		while (mid_blk != first_blk) and (mid_blk != end_blk):
			_err, _o = self._xlog_bread(mid_blk, 1)
			if _err:
				return _err, None
			mid_cycle = self._xlog_get_cycle(_o)
			if mid_cycle == cycle:
				end_blk = mid_blk
			else:
				first_blk = mid_blk
			mid_blk = BLK_AVG(first_blk, end_blk)
	
		return 0, end_blk

	def _xlog_find_verify_cycle(self, start_blk, nbblks, stop_on_cycle_no):

		bufblks = self._logBBsize
		new_blk = -9
		for _i in range(start_blk, start_blk + nbblks, bufblks):
			bcount = min(bufblks, (start_blk + nbblks - _i))
			_err, _o = self._xlog_bread(_i, bcount)
			if _err:
				return _err, new_blk
			for _j in range(0, bcount, 1):
				cycle = self._xlog_get_cycle(_o)
				if cycle == stop_on_cycle_no:
					new_blk = _i + _j
					return _err, new_blk
				_o += BBSIZE
		new_blk = -1

		return _err, new_blk

	def _xlog_header_check_mount(self, head):

		if platform_uuid_is_null(head.h_fs_uuid):
			return 0
		if header_check_uuid(self.superblocks[0][0], head):
			for _i in range(len(self.superblocks)):
				self.superblocks[_i][0].sb_uuid = head.h_fs_uuid

		return 0

	def _xlog_find_verify_log_record(self, start_blk, last_blk, extra_bblks):

		num_blks = last_blk - start_blk
		_err, _o = self._xlog_bread(start_blk, num_blks)
		if _err:
			return _err, -9

		_o += ((num_blks -1) << BBSHIFT)
		_j = 0
		for _i in range(last_blk -1, 0, -1):
			_j = _i
			if _i < start_blk:
				return _err, -9
			self.in_fd.seek(_o)
			_ptr = self.in_fd.read(sizeof(xlog_rec_header))
			_rec_header = copy.deepcopy(New(_ptr, xlog_rec_header))
			if cpu_to_be32(_rec_header.h_magicno) == XLOG_HEADER_MAGIC:
				break
			_o -= BBSIZE

		if _j == -1:
			_err = -1

		_err = self._xlog_header_check_mount(_rec_header)
		if _err:
			return _err
		if xfs_has_logv2(self._m_features):
			h_size = cpu_to_be32(_rec_header.h_size)
			xhdrs = h_size // XLOG_HEADER_CYCLE_SIZE
			if h_size % XLOG_HEADER_CYCLE_SIZE:
				xhdrs +=1
		else:
			xhdrs = 1
		if (last_blk - _j + extra_bblks) != (BTOBB(cpu_to_be32(_rec_header.h_len))+ xhdrs):
			last_blk = _j

		return 0, last_blk

	def _xlog_find_zeroed(self):

		_err, _o = self._xlog_bread(0, 1)
		_first_cycle = self._xlog_get_cycle(_o)
		if _first_cycle == 0:
			return 0

		_err, _o = self._xlog_bread((self._logBBsize -1), 1)
		_last_cycle = self._xlog_get_cycle(_o)
		if _last_cycle!= 0:
			return 0, _first_cycle
		if _first_cycle != 1:
			return -1, _first_cycle

		_err, _last_blk = self._xlog_find_cycle_start(0, (self._logBBsize -1), 0)
		if _err:
			return _err

		num_scan_bblks = XLOG_TOTAL_REC_SHIFT(self._m_features)
		if _last_blk < num_scan_bblks:
			num_scan_bblks = _last_blk
		start_blk = _last_blk - num_scan_bblks

		_err, _new_blk = self._xlog_find_verify_cycle(start_blk, num_scan_bblks, 0)
		if _err:
			return _err, -9
		if _new_blk != -1:
			_last_blk = new_blk

		_err, _last_blk = self._xlog_find_verify_log_record(start_blk, _last_blk, 0)
		if _err == -1:
			return 5, None
		if _err:
			return _err, None

		blk_no = _last_blk
		if _err:
			return _err, blk_no

		return -1, blk_no

	def _xlog_proc_find_oldest(self, last_blk):

		_err = 0
		_r, _first_blk = self._xlog_find_zeroed()
		if _r:
			return 0, last_blk

		_first_blk = 0
		_o = self._xlog_bread_noalign(0,1)
		first_half_cycle = self._xlog_get_cycle(_o)
		last_blk = self._logBBsize -1
		_o = self._xlog_bread_noalign(last_blk, 1)
		last_half_cycle =  self._xlog_get_cycle(_o)
		if first_half_cycle == last_half_cycle:
			last_blk = 0
		else:
			_err, last_blk = self._xlog_find_cycle_start(_first_blk, last_blk, last_half_cycle)

		return _err, last_blk

	def _xlog_lseek(self, blkno, whence):

		if whence == os.SEEK_SET:
			_o = BBTOOFF64(blkno + self._logBBstart)
		else:
			_o = BBTOOFF64(blkno)
		return _o

	def _xlog_proc_rec_head(self, rec_header, length):

		if not cpu_to_be32(rec_header.h_magicno):
			return ZEROED_LOG, length
		if cpu_to_be32(rec_header.h_magicno) != XLOG_HEADER_MAGIC:
			return BAD_HEADER, length

		_h_len = cpu_to_be32(rec_header.h_len)
		_h_crc = cpu_to_le32(rec_header.h_crc)
		_h_prev_block = cpu_to_be32(rec_header.h_prev_block)
		_h_num_logops = cpu_to_be32(rec_header.h_num_logops)
		_h_size = cpu_to_be32(rec_header.h_size)
		if (not _h_len) and (not _h_crc) and (not _h_prev_block) and (not _h_num_logops) and (not _h_size):
			return CLEARED_BLKS, length

		return _h_num_logops, _h_len

	def _xlog_reallocate_xhdrs(self, num_hdrs):

		_ret_xhdrs = []
		for _i in range((num_hdrs - 1)):
			_ext = xlog_rec_ext_header()
			_ret_xhdrs.append(copy.deepcopy(_ext))
		return _ret_xhdrs

	def _xlog_proc_extended_headers(self, length, blkno, hdr, ret_num_hdrs, ret_xhdrs):

		_blkno = blkno
		_r = 0
		_ret_num_hdrs = ret_num_hdrs
		_ret_xhdrs = ret_xhdrs
		_coverage_bb = 0
		_num_required = howmany(length, XLOG_HEADER_CYCLE_SIZE)
		_num_hdrs = cpu_to_be32(hdr.h_size) // XLOG_HEADER_CYCLE_SIZE
		if (cpu_to_be32(hdr.h_size) % XLOG_HEADER_CYCLE_SIZE):
			_num_hdrs += 1
		if _num_required > _num_hdrs:
			sys.exit(-1)
		if _num_hdrs == 1:
			_r = 0
			_ret_xhdrs = None
			_ret_num_hdrs = 1
			return _r, _blkno, _ret_xhdrs, _ret_num_hdrs
		if (_ret_xhdrs == None) or (_num_hdrs > _ret_num_hdrs):
			_ret_xhdrs = self._xlog_reallocate_xhdrs(_num_hdrs)

		_ret_num_hdrs = _num_hdrs
		for _i in range(1, _num_hdrs, 1):
			if (self.cur_pos + 512) > self.in_f_size:
				_r = 1
				return _r, _blkno, _ret_xhdrs, _ret_num_hdrs
			else:
				self.in_fd.seek(self.cur_pos)
				_ptr = self.in_fd.read(sizeof(xlog_rec_ext_header))
				_rec_ext_header = copy.deepcopy(New(_ptr, xlog_rec_ext_header))
				self.cur_pos += 512
			if _i == (_num_hdrs - 1):
				_coverage_bb = BTOBB(length) % (XLOG_HEADER_CYCLE_SIZE // BBSIZE)
			else:
				_coverage_bb = XLOG_HEADER_CYCLE_SIZE // BBSIZE

			_ret_xhdrs[_i - 1].xh_cycle = _rec_ext_header.xh_cycle
			for _j in range(0, (XLOG_HEADER_CYCLE_SIZE // BBSIZE), 1):
				_ret_xhdrs[_i - 1].xh_cycle_data[_j] = _rec_ext_header.xh_cycle_data[_j]

			_blkno += 1

		return _r, _blkno, _ret_xhdrs, _ret_num_hdrs

	def _xlog_proc_find_tid(self, tid, was_cont):

		_listp = self.split_list
		if not _listp:
			if was_cont != 0:
				return 1
			else:
				return 0

		while _listp:
			if _listp.si_xtid == tid:
				break
			_listp = _listp.si_next

		if not _listp:
			return 0

		_listp.si_skip -= 1
		if _listp.si_skip == 0:
			self.split_list = _listp.si_next
			if self.split_list:
				split_list.si_prev = None
		else:
			if _listp.si_next:
				_listp.si_next.si_prev = _listp.si_prev
				_listp.si_prev.si_next = _listp.si_next

		return 1

	def _xlog_proc_add_to_trans(self, tid, skip):

		_item = xlog_split_item()
		_item.si_xtid = tid
		_item.si_skip = skip
		_item.si_next = self.split_list
		_item.si_prev = None
		if self.split_list:
			split_list.si_prev = _item

		self.split_list = _item

	def _xfs_dir2_data_unused_tag_p(self, length):
		_pos = cpu_to_be16(length) - sizeof(c_int16)
		return _pos

	def _xfs_dir2_data_entsize(self, n):

		_pos = xfs_dir2_data_entry.namelen.offset + sizeof(c_uint8) + n
		if xfs_has_ftype(self._m_features):
			_pos += sizeof(c_uint8)
		_pos += sizeof(xfs_dir2_data_off)
		_size = roundup(_pos, XFS_DIR2_DATA_ALIGN)

		return _size

	def _xfs_dir2_data_entry_tag_p(self, namelen):
		_pos = self._xfs_dir2_data_entsize(namelen) - sizeof(xfs_dir2_data_off)
		return _pos

	def _xfs_dir2_sf_entsize(self, dir2_sf_hdr, length):

		_pos = xfs_dir2_sf_entry.offset.offset + sizeof(xfs_dir2_sf_off)
		_pos += length
		if dir2_sf_hdr.i8count:
			_pos += XFS_INO64_SIZE
		else:
			_pos += XFS_INO32_SIZE
		if xfs_has_ftype(self._m_features):
			_pos += sizeof(c_uint8)

		return _pos

	def _xfs_dir2_sf_get_ino(self, ptr, dir2_sf_hdr):

		_dir2_sf_entry = copy.deepcopy(New(ptr, xfs_dir2_sf_entry))
		_pos = xfs_dir2_sf_entry.offset.offset + sizeof(xfs_dir2_sf_off) + _dir2_sf_entry.namelen
		if xfs_has_ftype(self._m_features):
			_pos += sizeof(c_uint8)
		if len(ptr[_pos:]) < 4:
			return None
		if not dir2_sf_hdr.i8count:
			return get_unaligned_be32(ptr[_pos:])
		if len(ptr[_pos:]) < 8:
			return None

		return get_unaligned_be64(ptr[_pos:]) & XFS_MAXINUMBER

	def _xlog_proc_op_header(self, ptr,idx, num_ops, op_head):

		ptr = ptr[sizeof(xlog_op_header):]
		if self.trans:
			print("%04d)\t%d/%d, 0x%x(%d), 0x%x" % (sys._getframe(1).f_lineno, idx, num_ops, cpu_to_be32(op_head.oh_len), cpu_to_be32(op_head.oh_len), cpu_to_be32(op_head.oh_tid)), file = sys.stdout)

		return ptr

	def _xlog_proc_trans_header(self, ptr, length):

		_trans_header = copy.deepcopy(New(ptr, xfs_trans_header))
		if length != sizeof(xfs_trans_header):
			return -1, ptr

		ptr = ptr[length:]

		return 0, ptr

	def _xlog_proc_record(self, num_ops, length, partial_buf, rec_header, xhdrs, read_type, first_hdr_found):

		_buf = None
		_r = 0
		_lost_context = 0
		_skip = 0
		if not length:
			return NO_ERROR, read_type, partial_buf

		read_len = BBTOB(BTOBB(length))

		if read_type == FULL_READ:
			pass
		else:
			read_len -= read_type

		self.in_fd.seek(self.cur_pos)
		_ptr = self.in_fd.read(read_len)
		_r = read_len
		self.cur_pos += read_len
		if (read_type == FULL_READ) and ((BLOCK_LSN(cpu_to_be64(rec_header.h_lsn)) + BTOBB(read_len)) >= self._logBBsize):
			read_type = BBTOB(self._logBBsize - BLOCK_LSN(cpu_to_be64(rec_header.h_lsn)) -1)
			partial_buf = _ptr
			return PARTIAL_READ, read_type, partial_buf
		if (_r == 0 and read_len != 0) or (_r != read_len):
			read_type = _r
			partial_buf = _ptr
			return PARTIAL_READ, read_type, partial_buf
		if read_type != FULL_READ:
			read_len += read_type

		_i = 0
		_tid = None
		if partial_buf != None:
			_ptr = partial_buf[0:read_type] + _ptr

		for _off in range(0, read_len, BBSIZE):
			_rh = _ptr[_off:]
			_rechead = copy.deepcopy(New(_rh, xlog_rec_header))
			if cpu_to_be32(_rechead.h_magicno) == XLOG_HEADER_MAGIC:
				return BAD_HEADER, read_type, partial_buf
			else:
				_su = copy.deepcopy(New(_rh, sig_union))
				if cpu_to_be32(rec_header.h_cycle) != cpu_to_be32(_su.sig32):
					if (read_type == FULL_READ) or ((cpu_to_be32(rec_header.h_cycle) + 1) != cpu_to_be32(_su.sig32)):
						return BAD_HEADER, read_type, partial_buf
			if _i < XLOG_HEADER_CYCLE_SIZE // BBSIZE:
				_ptr = _ptr[0:_off] + rec_header.h_cycle_data[_i].to_bytes(4, sys.byteorder) + _ptr[_off+4:]
			else:
				_j = _i // (XLOG_HEADER_CYCLE_SIZE // BBSIZE)
				_k = _i % (XLOG_HEADER_CYCLE_SIZE // BBSIZE)
				_ptr = _ptr[0:_off] + xhdrs[_j-1].xh_cycle_data[_k].to_bytes(4, sys.byteorder) + _ptr[_off+4:]

			_i += 1

		_i = 0
		while _i < num_ops:
			_op_head = copy.deepcopy(New(_ptr, xlog_op_header))
			_ptr = self._xlog_proc_op_header(_ptr, _i, num_ops, _op_head)
			_continued = ((_op_head.oh_flags & XLOG_WAS_CONT_TRANS) or (_op_head.oh_flags & XLOG_CONTINUE_TRANS))
			if _continued and cpu_to_be32(_op_head.oh_len) == 0:
				continue
			if self._xlog_proc_find_tid(cpu_to_be32(_op_head.oh_tid), _op_head.oh_flags & XLOG_WAS_CONT_TRANS):
				_ptr = _ptr[cpu_to_be32(_op_head.oh_len):]
				_lost_context = 1
				_i += 1
				continue
			if cpu_to_be32(_op_head.oh_len) != 0:
				_su = copy.deepcopy(New(_ptr, sig_union))
				if _su.sig32 == XFS_TRANS_HEADER_MAGIC:
					_skip, _ptr = self._xlog_proc_trans_header(_ptr, cpu_to_be32(_op_head.oh_len))
				else:
					if _su.sig16 == XFS_LI_INODE:
						_skip, _i, _ptr = self._xlog_proc_trans_inode(_ptr, cpu_to_be32(_op_head.oh_len), _i, num_ops, _continued, _op_head)
					elif _su.sig16 == XFS_LI_BUF:
						_skip, _i, _ptr = self._xlog_proc_trans_buffer(_ptr, cpu_to_be32(_op_head.oh_len), _i, num_ops)
					elif _su.sig16 == XFS_LI_ICREATE:
						_skip, _i, _ptr = self._xlog_proc_trans_icreate(_ptr, cpu_to_be32(_op_head.oh_len), _op_head, _i, num_ops)
					elif _su.sig16 == XLOG_UNMOUNT_TYPE:
						_skip = 0
					else:
						_skip = 0
						_ptr = _ptr[cpu_to_be32(_op_head.oh_len):]
						_lost_context = 0
				if _skip != 0:
					self._xlog_proc_add_to_trans(cpu_to_be32(_op_head.oh_tid), _skip)
			_i += 1

		return NO_ERROR, read_type, partial_buf

	def _xlog_proc_trans_inode(self, ptr, length, i, num_ops, continued, op_header = None):

		_i = i + 1
		_ptr = ptr[length:]
		if not continued:
			if length == sizeof(xfs_inode_log_format):
				_src_lbuf = copy.deepcopy(New(ptr, xfs_inode_log_format))
			elif length == sizeof(xfs_inode_log_format_32):
				_src_lbuf = copy.deepcopy(New(ptr, xfs_inode_log_format_32))
			else:
				_src_lbuf = copy.deepcopy(New(ptr, xfs_inode_log_format))
				return _src_lbuf.ilf_size, _i, _ptr
		else:
			_src_lbuf = copy.deepcopy(New(ptr, xfs_inode_log_format))
			return _src_lbuf.ilf_size, _i, _ptr

		_skip_count = _src_lbuf.ilf_size - 1
		if _i >= num_ops:
			return _skip_count, _i, _ptr

		_op_head = copy.deepcopy(New(_ptr, xlog_op_header))
		_ptr = self._xlog_proc_op_header(_ptr, _i, num_ops, _op_head)
		if (_op_head.oh_flags & XLOG_CONTINUE_TRANS):
			return _skip_count, _i, _ptr

		_dinode = copy.deepcopy(New(_ptr, xfs_log_dinode))
		_mode = _dinode.di_mode & S_IFMT
		_size = _dinode.di_size
		self._xlog_proc_trans_inode_core(_dinode, _src_lbuf, _op_head, _i, num_ops)
		_ptr = _ptr[xfs_log_dinode_size(self._m_features):]
		_skip_count -= 1
		if _src_lbuf.ilf_size == 2:
			return 0, _i, _ptr

		_op_head = copy.deepcopy(New(_ptr, xlog_op_header))
		if (_src_lbuf.ilf_fields & XFS_ILOG_DFORK):
			if _i == (num_ops - 1):
				return _skip_count, _i, _ptr
			_i += 1
			_ptr = self._xlog_proc_op_header(_ptr, _i, num_ops, _op_head)
			if ((_src_lbuf.ilf_fields & XFS_ILOG_DFORK) & XFS_ILOG_DDATA):
				if _mode == S_IFDIR:
					self._xlog_proc_dir2_sf(_ptr, _size, _src_lbuf,_op_head, _i, num_ops)
				if _mode == S_IFLNK:
					self._xlog_proc_sl_sf(_ptr, _size, _src_lbuf,_op_head, _i, num_ops)
			elif ((_src_lbuf.ilf_fields & XFS_ILOG_DFORK) & XFS_ILOG_DEXT):
				if _mode == S_IFDIR:
					self._xlog_proc_dir2_blk(_ptr, _size, _src_lbuf,_op_head, _i, num_ops, _dinode)
				if _mode == S_IFLNK:
					self._xlog_proc_sl_blk(_ptr, _size, _src_lbuf,_op_head, _i, num_ops, _dinode)
			elif ((_src_lbuf.ilf_fields & XFS_ILOG_DFORK) & XFS_ILOG_DBROOT):
				if _mode == S_IFDIR:
					self._xlog_proc_dir2_btree(_ptr, _size, _src_lbuf,_op_head, _i, num_ops, _dinode, True)

			_ptr = _ptr[cpu_to_be32(_op_head.oh_len):]
			if _op_head.oh_flags & XLOG_CONTINUE_TRANS:
				return _skip_count, _i, _ptr

			_op_head = copy.deepcopy(New(_ptr, xlog_op_header))
			_skip_count -= 1

		if (_src_lbuf.ilf_fields & XFS_ILOG_AFORK):
			if _i == (num_ops - 1):
				return _skip_count, _i, _ptr
			_i += 1
			_ptr = self._xlog_proc_op_header(_ptr, _i, num_ops, _op_head)
			if ((_src_lbuf.ilf_fields & XFS_ILOG_AFORK) & XFS_ILOG_ADATA):
				self._xlog_proc_attr_sf(_ptr, _size, _src_lbuf, _op_head, _i, num_ops)
			elif ((_src_lbuf.ilf_fields & XFS_ILOG_AFORK) & XFS_ILOG_AEXT):
				self._xlog_proc_attr_blk(_ptr, _size, _src_lbuf, _op_head, _i, num_ops, _dinode)
			elif ((_src_lbuf.ilf_fields & XFS_ILOG_AFORK) & XFS_ILOG_ABROOT):
				self._xlog_proc_attr_btree(_ptr, _size, _src_lbuf, _op_head, _i, num_ops, _dinode)
			_ptr = _ptr[cpu_to_be32(_op_head.oh_len):]

			if _op_head.oh_flags & XLOG_CONTINUE_TRANS:
				return _skip_count, _i, _ptr

			_skip_count -= 1

		return 0, _i, _ptr

	def _xlog_proc_trans_buffer(self, ptr, length, i, num_ops):

		_head = None
		_lbuf = copy.deepcopy(New(ptr, xfs_buf_log_format))
		_i = i
		_super_block = 0
		_blkno = _lbuf.blf_blkno
		_map_size = _lbuf.blf_map_size
		_size = _lbuf.blf_size
		_struct_size = xfs_buf_log_format.blf_map_size.offset + _map_size
		_blf_flags = _lbuf.blf_flags
		_blft_flags = _lbuf.blf_flags >> XFS_BLFT_SHIFT
		_ptr = ptr[length:]
		if length >= _struct_size:
			if _blkno == 0:
				_super_block = 1
		else:
			return _size, _i, _ptr

		_num = _size - 1
		if (_i + _num) > (num_ops - 1):
			_skip = _num - (num_ops - 1 - _i)
			_num = num_ops - 1 - _i
		else:
			_skip = 0

		while _num > 0:
			_num -= 1
			_i += 1
			_head = copy.deepcopy(New(_ptr, xlog_op_header))
			_length = cpu_to_be32(_head.oh_len)
			_ptr = self._xlog_proc_op_header(_ptr, _i, num_ops, _head)
			_su = copy.deepcopy(New(_ptr, sig_union))
			if _super_block:
				if cpu_to_be32(_head.oh_len) < (4 * 8):
					pass
				else:
					_super_block = 0
			elif  cpu_to_be32(_su.sig32) == XFS_AGI_MAGIC:
				if cpu_to_be32(_head.oh_len) < (xfs_agi.agi_uuid.offset - XFS_AGI_UNLINKED_BUCKETS * sizeof(xfs_agino)):
					pass
				else:
					pass
			elif cpu_to_be32(_su.sig32) == XFS_AGF_MAGIC:
				if cpu_to_be32(_head.oh_len) < xfs_agf.agf_uuid.offset:
					pass
				else:
					pass
			elif cpu_to_be16(_su.sig16) == XFS_DQUOT_MAGIC:
				if cpu_to_be32(_head.oh_len) < sizeof(xfs_disk_dquot):
					pass
				else:
					pass
			elif cpu_to_be16(_su.sig16) == XFS_DINODE_MAGIC:
				pass
			elif cpu_to_be32(_su.sig32) == XFS_DIR2_BLOCK_MAGIC:
				_dir2_data_hdr = copy.deepcopy(New(_ptr, xfs_dir2_data_hdr))
				self._xlog_proc_xfs_dir2(_ptr[sizeof(xfs_dir2_data_hdr):_length], _dir2_data_hdr, _head, _i, num_ops, XFS_DIR2_BLOCK_MAGIC)
			elif cpu_to_be32(_su.sig32) == XFS_DIR3_BLOCK_MAGIC:
				_dir3_data_hdr = copy.deepcopy(New(_ptr, xfs_dir3_data_hdr))
				self._xlog_proc_xfs_dir2(_ptr[sizeof(xfs_dir3_data_hdr):_length], _dir3_data_hdr, _head, _i, num_ops, XFS_DIR3_BLOCK_MAGIC)
			elif cpu_to_be32(_su.sig32) == XFS_DIR2_DATA_MAGIC:
				_dir2_data_hdr = copy.deepcopy(New(_ptr, xfs_dir2_data_hdr))
				self._xlog_proc_xfs_dir2(_ptr[sizeof(xfs_dir2_data_hdr):_length], _dir2_data_hdr, _head, _i, num_ops, XFS_DIR2_DATA_MAGIC)
			elif cpu_to_be32(_su.sig32) == XFS_DIR3_DATA_MAGIC:
				_dir3_data_hdr = copy.deepcopy(New(_ptr, xfs_dir3_data_hdr))
				self._xlog_proc_xfs_dir2(_ptr[sizeof(xfs_dir3_data_hdr):_length], _dir3_data_hdr, _head, _i, num_ops, XFS_DIR3_DATA_MAGIC)

			_ptr = _ptr[_length:]

		if _head and (_head.oh_flags & XLOG_CONTINUE_TRANS):
			_skip += 1

		return _skip, _i, _ptr

	def _xlog_proc_trans_icreate(self, ptr, length, op_head, i, num_ops):

		_ptr = ptr[length:]
		if length != sizeof(xfs_icreate_log):
			return 1, i, _ptr

		_icreate_log = copy.deepcopy(New(ptr, xfs_icreate_log))
		_icl_ag = cpu_to_be32(_icreate_log.icl_ag)
		_icl_agbno = cpu_to_be32(_icreate_log.icl_agbno)
		_icl_count = cpu_to_be32(_icreate_log.icl_count)
		_icl_isize = cpu_to_be32(_icreate_log.icl_isize)
		_icl_length = cpu_to_be32(_icreate_log.icl_length)
		_icl_gen = cpu_to_be32(_icreate_log.icl_gen)

		for _i in range(_icl_count):
			_ino = self._get_inode_number(_icl_ag, _icl_agbno, _icl_isize * _i)
			_offset = self._get_inode_offset(_ino)
			if _offset is None:
				continue

			print("0x%x,%d/%d,XFS_LI_ICREATE,-,0x%x(%d),-,-,-,-,-,-,-,-,-,-,-,-,\"{%sicl_count%s:%s%d/%d%s,%soffset%s:%s0x%x(%d)%s,%sicl_ag%s:%s%d%s,%sicl_agbno%s:%s%d%s,%sicl_gen%s:%s0x%x%s}\"" \
					% \
					(cpu_to_be32(op_head.oh_tid),\
					i,num_ops,\
					_ino,_ino,\
					q,q,q,_i,_icl_count,q,\
					q,q,q,_offset,_offset,q,\
					q,q,q,_icl_ag,q,
					q,q,q,_icl_agbno,q,\
					q,q,q,_icl_gen,q
					), file = self.out_fd)

		return 0, i, _ptr

	def _xlog_proc_trans_inode_core(self, dinode, src_lbuf, op_head, i, num_ops, is_bigendian = False):

		if xfs_dinode_has_bigtime(dinode.di_version, dinode.di_flags2, is_bigendian):
			_atime = timestamp_to_str(dinode.di_atime, is_bigendian)
			_mtime = timestamp_to_str(dinode.di_mtime, is_bigendian)
			_ctime = timestamp_to_str(dinode.di_ctime, is_bigendian)
			_crtime = timestamp_to_str(dinode.di_crtime, is_bigendian)
		else:
			_atime = legacy_timestamp_to_str(dinode.di_atime, is_bigendian)
			_mtime = legacy_timestamp_to_str(dinode.di_mtime, is_bigendian)
			_ctime = legacy_timestamp_to_str(dinode.di_ctime, is_bigendian)
			_crtime = legacy_timestamp_to_str(dinode.di_crtime, is_bigendian)

		_data_fork_type_str = conv_type_to_str(get_type(dinode.di_mode, is_bigendian))
		if dinode.di_version != 0x03:
			_crtime = "-"

		_ino = src_lbuf.ilf_ino
		if is_bigendian:
			_ino = cpu_to_be64(dinode.di_ino)

		_mode = dinode.di_mode
		_uid = dinode.di_uid
		_gid = dinode.di_gid
		_size = dinode.di_size
		if is_bigendian:
			_mode = cpu_to_be16(dinode.di_mode)
			_uid = cpu_to_be32(dinode.di_uid)
			_gid = cpu_to_be32(dinode.di_gid)
			_size = cpu_to_be64(dinode.di_size)

		print("0x%x,%d/%d,XFS_LI_INODE,XFS_ILOG_CORE,0x%x(%d),-,0o%o,%d,%d,%d,%s,%s,%s,%s,-,%s,-,{}" \
				% \
				(cpu_to_be32(op_head.oh_tid),\
				i, num_ops,\
				_ino,_ino,\
				_mode,\
				_uid,\
				_gid,\
				_size,\
				_atime,\
				_mtime,\
				_ctime,\
				_crtime,\
				_data_fork_type_str
				), file = self.out_fd)

	def _xlog_proc_dir2_sf(self, ptr, size, src_lbuf, op_head, i, num_ops):

		_namebuf = ""
		_dir2_sf_hdr = copy.deepcopy(New(ptr, xfs_dir2_sf_hdr))
		if _dir2_sf_hdr.i8count > 0:
			_pino = array_to_num(_dir2_sf_hdr.parent.i8)
			_count = _dir2_sf_hdr.i8count
		else:
			_pino = array_to_num(_dir2_sf_hdr.parent.i4)
			_count = _dir2_sf_hdr.count

		ptr = ptr[_dir2_sf_hdr.size():]

		for _i in range(0, _count, 1):
			_ino = self._xfs_dir2_sf_get_ino(ptr, _dir2_sf_hdr)
			if _ino is None:
				break
			_dir2_sf_entry = copy.deepcopy(New(ptr, xfs_dir2_sf_entry))
			_pos = xfs_dir2_sf_entry.offset.offset + sizeof(xfs_dir2_sf_off)
			_namebuf = ptr[_pos:(_pos+_dir2_sf_entry.namelen)].decode('utf-8', errors='ignore')
			_ftype_str = "-"
			if xfs_has_ftype(self._m_features):
				_ftype = ptr[_pos+_dir2_sf_entry.namelen]
				_ftype_str = xfs_dir3_ft(_ftype).name

			print("0x%x,%d/%d,XFS_LI_INODE,XFS_ILOG_DDATA,0x%x(%d),\"%s\",-,-,-,-,-,-,-,-,%s,-,0x%x(%d),{}" \
					% \
					(cpu_to_be32(op_head.oh_tid),\
					i,num_ops,\
					_ino,_ino,\
					_namebuf,\
					_ftype_str,\
					_pino,_pino
					), file = self.out_fd)

			_pos = self._xfs_dir2_sf_entsize(_dir2_sf_hdr, _dir2_sf_entry.namelen)
			ptr = ptr[_pos:]

	def _xlog_proc_dir2_blk(self, ptr, size, src_lbuf,op_head, i, num_ops, dinode):

		_ino = src_lbuf.ilf_ino
		print("0x%x,%d/%d,XFS_LI_INODE,XFS_ILOG_DEXT,0x%x(%d),\"-\",-,-,-,-,-,-,-,-,-,-,-,\"{%smemo%s:%s_xlog_proc_dir2_blk is not implemented.%s}\"" \
				% \
				(cpu_to_be32(op_head.oh_tid),\
				i,num_ops,\
				_ino,_ino,\
				q,q,q,q
				), file = self.out_fd)

	def _xlog_proc_dir2_btree(self, ptr, size, src_lbuf,op_head, i, num_ops, dinode, is_root):

		_ino = src_lbuf.ilf_ino
		print("0x%x,%d/%d,XFS_LI_INODE,XFS_ILOG_DBROOT,0x%x(%d),\"-\",-,-,-,-,-,-,-,-,-,-,-,\"{%smemo%s:%s_xlog_proc_dir2_btree is not implemented.%s}\"" \
				% \
				(cpu_to_be32(op_head.oh_tid),\
				i,num_ops,\
				_ino,_ino,\
				q,q,q,q
				), file = self.out_fd)

	def _xlog_proc_sl_sf(self, ptr, size, src_lbuf, op_head, i, num_ops):

		_ino = src_lbuf.ilf_ino
		print("0x%x,%d/%d,XFS_LI_INODE,XFS_ILOG_DDATA,0x%x(%d),-,-,-,-,-,-,-,-,-,-,-,-,\"{%sdi_symlink%s:%s%s%s}\"" \
				% \
				(cpu_to_be32(op_head.oh_tid),\
				i,num_ops,\
				_ino,_ino,\
				q,q,q,ptr[:size].decode('utf-8'),q
				), file = self.out_fd)

	def _xlog_proc_sl_blk(self, ptr, size, src_lbuf, op_head, i, num_ops, dinode):

		_ino = src_lbuf.ilf_ino
		print("0x%x,%d/%d,XFS_LI_INODE,XFS_ILOG_DEXT,0x%x(%d),-,-,-,-,-,-,-,-,-,-,-,-,\"{%smemo%s:%s_xlog_proc_sl_blk is not implemented.%s}\"" \
				% \
				(cpu_to_be32(op_head.oh_tid),\
				i,num_ops,\
				_ino,_ino,\
				q,q,q,q
				), file = self.out_fd)

	def _xlog_proc_attr_sf(self, ptr, size, src_lbuf, op_head, i, num_ops):

		_ino = src_lbuf.ilf_ino
		_attr_sf_hdr = copy.deepcopy(New(ptr, xfs_attr_sf_hdr))
		_totsize = cpu_to_be16(_attr_sf_hdr.totsize)
		_count = _attr_sf_hdr.count
		ptr = ptr[sizeof(xfs_attr_sf_hdr):]
		for _i in range(0, _count, 1):
			_attr_sf_entry = copy.deepcopy(New(ptr, xfs_attr_sf_entry))
			_namelen = _attr_sf_entry.namelen
			_valuelen = _attr_sf_entry.valuelen
			_flags = _attr_sf_entry.flags
			ptr = ptr[xfs_attr_sf_entry.nameval.offset:]
			_name = ptr[:_namelen].decode('utf-8', errors='ignore').replace('\x00','')
			ptr = ptr[_namelen:]
			if len(ptr) < 1:
				break
			try:
				_value = ptr[:_valuelen].decode('utf-8').replace('\x00','').replace('"','""')
			except:
				_value = "0x" + ptr[:_valuelen].hex()

			_flags_str = ""
			if _flags & XFS_ATTR_LOCAL:
				_flags_str = "XFS_ATTR_LOCAL"
			if _flags & XFS_ATTR_ROOT:
				if len(_flags_str) > 0:
					_flags_str = _flags_str + "|"
				_flags_str = _flags_str + "XFS_ATTR_ROOT"
			if _flags & XFS_ATTR_SECURE:
				if len(_flags_str) > 0:
					_flags_str = _flags_str + "|"
				_flags_str = _flags_str + "XFS_ATTR_SECURE"
			if _flags & XFS_ATTR_PARENT:
				if len(_flags_str) > 0:
					_flags_str = _flags_str + "|"
				_flags_str = _flags_str + "XFS_ATTR_PARENT"
			if _flags & XFS_ATTR_INCOMPLETE:
				if len(_flags_str) > 0:
					_flags_str = _flags_str + "|"
				_flags_str = _flags_str + "XFS_ATTR_INCOMPLETE"

			print("0x%x,%d/%d,XFS_LI_INODE,XFS_ILOG_ADATA,0x%x(%d),-,-,-,-,-,-,-,-,-,-,-,-,\"{%sname%s:%s%s%s,%svalue%s:%s%s%s,%sflags%s:%s%s%s}\"" \
					% \
					(cpu_to_be32(op_head.oh_tid),\
					i,num_ops,\
					_ino,_ino,\
					q,q,q,_name,q,\
					q,q,q,_value,q,\
					q,q,q,_flags_str,q
					), file = self.out_fd)

			ptr = ptr[_valuelen:]

	def _xlog_proc_attr_blk(self, ptr, size, src_lbuf, op_head, i, num_ops, dinode):

		_ino = src_lbuf.ilf_ino
		print("0x%x,%d/%d,XFS_LI_INODE,XFS_ILOG_AEXT,0x%x(%d),\"-\",-,-,-,-,-,-,-,-,-,-,-,\"{%smemo%s:%s_xlog_proc_attr_blk is not implemented.%s}\"" \
				% \
				(cpu_to_be32(op_head.oh_tid),\
				i,num_ops,\
				_ino,_ino,\
				q,q,q,q
				), file = self.out_fd)

	def _xlog_proc_attr_btree(self, ptr, size, src_lbuf, op_head, i, num_ops, dinode):

		_ino = src_lbuf.ilf_ino
		print("0x%x,%d/%d,XFS_LI_INODE,XFS_ILOG_ABROOT,0x%x(%d),\"-\",-,-,-,-,-,-,-,-,-,-,-,\"{%smemo%s:%s_xlog_proc_attr_btree is not implemented.%s}\"" \
				% \
				(cpu_to_be32(op_head.oh_tid),\
				i,num_ops,\
				_ino,_ino,\
				q,q,q,q
				), file = self.out_fd)

	def _xlog_proc_xfs_dir2(self, ptr, hdr, op_head, i, num_ops, magic):

		_magic_str = ""
		if magic ==  XFS_DIR2_BLOCK_MAGIC:
			_magic_str = "XFS_DIR2_BLOCK_MAGIC"
		if magic ==  XFS_DIR3_BLOCK_MAGIC:
			_magic_str = "XFS_DIR3_BLOCK_MAGIC"
		if magic ==  XFS_DIR2_DATA_MAGIC:
			_magic_str = "XFS_DIR2_DATA_MAGIC"
		if magic ==  XFS_DIR3_DATA_MAGIC:
			_magic_str = "XFS_DIR3_DATA_MAGIC"

		_ptr = ptr
		_off = 0
		while len(ptr) > (_off + sizeof(xfs_dir2_data_union)):
			_dir2_data_union = copy.deepcopy(New(_ptr, xfs_dir2_data_union))
			_unused = _dir2_data_union.unused
			if _unused.freetag == 0xffff:
				_pos = self._xfs_dir2_data_unused_tag_p(_unused.length) + sizeof(c_int16)
				_ptr = _ptr[_pos:]
				_off += _pos
				continue

			_entry = _dir2_data_union.entry
			_ino = cpu_to_be64(_entry.inumber)
			_pos = xfs_dir2_data_entry.namelen.offset + sizeof(c_uint8)
			_namebuf = _ptr[_pos:(_pos + _entry.namelen)].decode('utf-8', errors='ignore')
			_pos += _entry.namelen
			_ftype = 0
			if xfs_has_ftype(self._m_features):
				if len(_ptr[_pos:]) < sizeof(c_uint8):
					break
				_ftype, = struct.unpack(">B", _ptr[_pos:(_pos + sizeof(c_uint8))])
				_pos += sizeof(c_uint8)

			_pos = self._xfs_dir2_data_entry_tag_p(_entry.namelen)
			if len(_ptr[_pos:]) < sizeof(xfs_dir2_data_off):
				break

			_tag, = struct.unpack(">H", _ptr[_pos:(_pos + sizeof(xfs_dir2_data_off))])
			if _off != (_tag - 0x40):
				break;

			_pos += sizeof(xfs_dir2_data_off)
			_ptr = _ptr[_pos:]
			_off += _pos
			_ftype_str = "-"
			if xfs_has_ftype(self._m_features):
				_ftype_str = xfs_dir3_ft(_ftype).name

			print("0x%x,%d/%d,XFS_LI_BUF,%s,0x%x(%d),\"%s\",-,-,-,-,-,-,-,-,%s,-,-,{}" \
					% \
					(cpu_to_be32(op_head.oh_tid),\
					i,num_ops,\
					_magic_str,\
					_ino,_ino,\
					_namebuf,\
					_ftype_str
					), file = self.out_fd)

	def _xfs_log_stat(self):

		_blkbb_log = self.superblocks[0][0].sb_blocklog - BBSHIFT;
		_logBBsize = XFS_FSB_TO_BB(cpu_to_be32(self.superblocks[0][0].sb_logblocks), _blkbb_log)
		_logBBstart = XFS_FSB_TO_DADDR(cpu_to_be64(self.superblocks[0][0].sb_logstart), \
										cpu_to_be32(self.superblocks[0][0].sb_agblocks), \
										self.superblocks[0][0].sb_agblklog, _blkbb_log)
		_sectBBsize = BTOBB(BBSIZE)
		self._blkbb_log = _blkbb_log
		self._logBBsize = _logBBsize
		self._logBBstart = _logBBstart
		self._sectBBsize = _sectBBsize

	def _set_logstart(self):

		self._xfs_log_stat()
		_err, _block_end = self._xlog_proc_find_oldest(0)
		_block_start = _block_end
		_o = self._xlog_lseek(_block_start, os.SEEK_SET)
		self.logstart = _o
		self.cur_pos = self.logstart
		_blkno = _block_start
		_read_type = FULL_READ
		_num_hdrs = 1
		_first_hdr_found = 0
		_cleared = 0
		_zeroed = 0
		_cleared_blkno = 0
		_zeroed_blkno = 0
		_read_type = FULL_READ
		_partial_buf = None
		_xhdrs = None

		_len = 0
		while True:
			self.in_fd.seek(self.cur_pos)
			_t = self.in_fd.read(sizeof(xlog_rec_header))
			_rec_header = copy.deepcopy(New(_t, xlog_rec_header))
			self.cur_pos += 512
			self.in_fd.seek(self.cur_pos)
			_num_ops, _len = self._xlog_proc_rec_head(_rec_header, _len)
			_blkno += 1
			if (_zeroed) and (_num_ops != ZEROED_LOG):
				print("ERROR: found data after zeroed blocks block=%d" % (_blkno - 1), file=sys.stderr)
				_zeroed = 0
			if (_num_ops == ZEROED_LOG) or (_num_ops == CLEARED_BLKS) or (_num_ops == BAD_HEADER):
				if _num_ops == ZEROED_LOG:
					if _zeroed == 0:
						zeroed_blk_no = _blkno - 1
					_zeroed += 1
				elif _num_ops == CLEARED_BLKS:
					if _cleared == 0:
						_cleared_blkno = _blkno - 1
					_cleared +=1
				else:
					if not _first_hdr_found:
						_block_start = _blkno
					else:
						print("* ERROR: header block=%d" % (_blkno - 1), file = sys.stderr)
			else:
				if cpu_to_be32(_rec_header.h_version) == 0x2:
					_r, _blkno, _xhdrs, _num_hdrs = self._xlog_proc_extended_headers(_len, _blkno, _rec_header, _num_hdrs, _xhdrs)
					if _r != 0:
						break
				_err, _read_type, _partial_buf = self._xlog_proc_record(_num_ops, _len, _partial_buf, _rec_header, _xhdrs, _read_type, _first_hdr_found)
				_first_hdr_found += 1
				if _err == NO_ERROR:
					_blkno += BTOBB(_len)
				elif _err == BAD_HEADER:
					_o = self._xlog_lseek(_blkno, os.SEEK_SET)
					self.cur_pos = _o
				elif _err == PARTIAL_READ:
					_blkno = 0
					_o = self._xlog_lseek(0, os.SEEK_SET)
					self.cur_pos = _o
					if _block_start == 0:
						return
					break
			if (_err != PARTIAL_READ) and (_blkno >= self._logBBsize):
				if _cleared:
					_cleared = 0
				if _zeroed:
					_zeroed = 0
				break

		if (_block_start != 0):
			if (_err != PARTIAL_READ):
				_blkno = 0
				_o = self._xlog_lseek(0, os.SEEK_SET)
				self.cur_pos = _o

			while True:
				if (_err != PARTIAL_READ):
					self.in_fd.seek(self.cur_pos)
					_ptr = self.in_fd.read(sizeof(xlog_rec_header))
					_rec_header = copy.deepcopy(New(_ptr, xlog_rec_header))
					self.cur_pos += 512
					self.in_fd.seek(self.cur_pos)
					_num_ops, _len = self._xlog_proc_rec_head(_rec_header, _len)
					_blkno += 1
					if (_num_ops == ZEROED_LOG) or (_num_ops == CLEARED_BLKS) or (_num_ops == BAD_HEADER):
						if _blkno >= _block_end:
							break
						continue
					if cpu_to_be32(_rec_header.h_version) == 2:
						_r, _blkno, _xhdrs, _num_hdrs = self._xlog_proc_extended_headers(_len, _blkno,_rec_header, _num_hdrs, _xhdrs)
						if _r != 0:
							break

				_err, _read_type, _partial_buf = self._xlog_proc_record(_num_ops, _len, _partial_buf, _rec_header, _xhdrs, _read_type, _first_hdr_found)
				if _read_type != FULL_READ:
					_len -= _read_type

				_read_type = FULL_READ
				_partial_buf = None
				if not _err:
					_blkno += BTOBB(_len)
				else:
					_o = self._xlog_lseek(_blkno, os.SEEK_SET)
					self.cur_pos = _o
				if _blkno >= _block_end:
					break

				_err = NO_ERROR

	def search_inodes(self):
		self._put_meta_header()
		self._load_inodes()

	def search_logs(self):
		self._put_journal_header()
		self._set_logstart()

	def __del__(self):
		if hasattr(self,"in_fd"):
			self.in_fd.close()
		if hasattr(self,"out_fd"):
			self.out_fd.close()

	def __init__(self, args):

		inf = args.input
		outf = args.output

		deleted = False
		if hasattr(args, "deleted"):
			deleted = args.deleted
		trans = False
		if hasattr(args, "trans"):
			trans = args.trans

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

		self.trans = trans
		self.cur_pos = 0
		self.oper = 0
		self.split_list = None
		self.in_fd = in_fd
		self.out_fd = out_fd
		self.deleted = deleted

		self._set_superblocks()
		self._set_inode_b_plus_tree_info()
		self._set_inode_range()
		self.in_fd.seek(0, os.SEEK_END)
		self.in_f_size = self.in_fd.tell()
		self.in_fd.seek(0)
