#ifndef FS_H
#define FS_H

#define FUSE_USE_VERSION 34

#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fuse3/fuse.h>

#include "uthash/src/uthash.h"

#define MAX_PATH_SEG 255
#define FS_BSIZE 4096

struct fs_entry;


struct fs_file {
	size_t len;
	size_t cap;
	char *buf;
};

struct fs_directory {
	struct fs_entry *direntries;
};

enum filetype {
	FS_NONE,
	FS_DIR,
	FS_FILE,
	FS_SYMLINK, /* TODO */
	FS_FILETYPE_NUM
};

struct fs_entry {
	struct fs_entry *parent;
	enum filetype type;
	char name[MAX_PATH_SEG + 1]; /* key */

	struct stat st;
	UT_hash_handle hh;

	union {
		struct fs_file f;
		struct fs_directory dir;
	};
};

void *fs_init(struct fuse_conn_info *conn, struct fuse_config *cfg);

int fs_getattr(const char *path, struct stat *st, struct fuse_file_info *fi);
int fs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags);
int fs_create(const char *path, mode_t mode, struct fuse_file_info *fi);
int fs_write(const char *path, const char *buf, size_t sz, off_t off, struct
		fuse_file_info *fi);
int fs_read(const char *path, char *buf, size_t sz, off_t off,
		struct fuse_file_info *fi);
int fs_unlink(const char *path);
int fs_rmdir(const char *path);
int fs_mkdir(const char *path, mode_t mode);
int fs_truncate(const char *path, off_t len, struct fuse_file_info *fi);
int fs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi);
void fs_destroy(void *private_data);
int fs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi);
int fs_symlink(const char *target, const char *path);
int fs_readlink(const char *path, char *buf, size_t bufsz);
int fs_utimens(const char *path, const struct timespec tv[2],
		struct fuse_file_info *fi);
int fs_statfs(const char *path, struct statvfs *stat);
int fs_rename(const char *old, const char *new, unsigned int flags);

#endif /* FS_H */
