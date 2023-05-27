#include "fs.h"

static struct fuse_operations fs_operations = {
	.getattr = fs_getattr,
	.readdir = fs_readdir,
	.create = fs_create,
	.write = fs_write,
	.read = fs_read,
	.unlink = fs_unlink,
	.rmdir = fs_rmdir,
	.mkdir = fs_mkdir,
	.truncate = fs_truncate,
	.chmod = fs_chmod,
	.destroy = fs_destroy,
	.init = fs_init,
	.chown = fs_chown,
	.symlink = fs_symlink,
	.readlink = fs_readlink,
};

int main(int argc, char *argv[]) {
	return fuse_main(argc, argv, &fs_operations, NULL);
}
