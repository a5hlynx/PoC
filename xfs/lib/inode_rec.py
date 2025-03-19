class InodeRec:

	def __init__(self):
		self.inode_num = 0
		self.name = ""
		self.parent_inode_num = 0
		self.parent_path = ""
		self.inode_core = None
		self.sl_target = ""
		self.attrs = []
		self.is_deleted = False
