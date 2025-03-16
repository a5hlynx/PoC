from lib.xfs import *
from argparse import ArgumentParser

def main():

	parser = ArgumentParser()
	parser.add_argument("-i", "--input", help="specify disk image", required=True)
	parser.add_argument("-o", "--output", help="specify output file", required=True)
	parser.add_argument("-t", "--trans", help="show transaction ids", required=False, action='store_true')
	args = parser.parse_args()

	xfs = XFS(args)
	xfs.search_logs()

if __name__ == '__main__':
	main()
