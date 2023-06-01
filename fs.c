#include "fs.h"

#include <libgen.h>
#include <fuse3/fuse_log.h>

#ifdef NASSERT
# define ASSERT(cond) (cond)
#else
# define ASSERT(cond)                                                          \
	do {                                                                      \
		if (!(cond)) {                                                        \
			fprintf(stderr, "%s:%d: Assertion failed\n", __FILE__, __LINE__); \
			exit(1);                                                          \
		}                                                                     \
	} while (0)
#endif

#ifdef NDEBUG_LOG
# define DEBUG_LOG(...)
#else
# define DEBUG_LOG(...) fuse_log(FUSE_LOG_DEBUG, __VA_ARGS__)
#endif

void *xmalloc_(size_t sz, char *file, int line) {
	void *ret = malloc(sz);
	memset(ret, 0x00, sz); /* NOTE dbg */
	if (!ret)
		fprintf(stderr, "%s:%d: xmalloc: Error allocating memory\n", file,
				line), exit(1);

	return ret;
}
#ifndef XMALLOC
#define XMALLOC(sz) xmalloc_((sz), __FILE__, __LINE__)
#endif

void *xrealloc_(void *ptr, size_t sz, char *file, int line) {
	void *ret = realloc(ptr, sz);
	if (!ret)
		fprintf(stderr, "%s:%d: xrealloc: Error allocating memory\n", file,
				line), exit(1);

	return ret;
}
#ifndef XREALLOC
#define XREALLOC(ptr, sz) xrealloc_((ptr), (sz), __FILE__, __LINE__)
#endif

#ifndef XFREE
#define XFREE free
#endif

static inline struct timespec get_time() {
	struct timespec tp = {0};
	ASSERT(clock_gettime(CLOCK_REALTIME, &tp) == 0);
	return tp;
}

struct fs_entry fs_new_dir(char *name, uid_t uid, gid_t gid, mode_t mode) {
	struct timespec now = get_time();

	struct fs_entry ret = {
		.st = {
			.st_uid = uid,
			.st_gid = gid,
			.st_mode = S_IFDIR | mode,
			.st_nlink = 2,
			.st_size = 4096,

			.st_ctim = now,
			.st_atim = now,
			.st_mtim = now,
		},
		.type = FS_DIR,
		.dir = { .direntries = NULL }
	};

	snprintf(ret.name, sizeof(ret.name), "%s", name);

	return ret;
}

struct fs_entry fs_new_file(char *name, uid_t uid, gid_t gid, mode_t mode) {
	struct timespec now = get_time();

	struct fs_entry ret = {
		.st = {
			.st_uid = uid,
			.st_gid = gid,
			.st_mode = S_IFREG | mode,
			.st_nlink = 1,
			.st_blksize = 4096,

			.st_ctim = now,
			.st_atim = now,
			.st_mtim = now,
		},
		.type = FS_FILE,
		.f = { .len = 0, .buf = NULL }
	};

	snprintf(ret.name, sizeof(ret.name), "%s", name);

	return ret;
}

struct fs_entry fs_new_symlink(char *name, uid_t uid, gid_t gid, mode_t mode) {
	struct timespec now = get_time();

	struct fs_entry ret = {
		.st = {
			.st_uid = uid,
			.st_gid = gid,
			.st_mode = S_IFLNK | mode,
			.st_nlink = 1,
			.st_blksize = 4096,

			.st_ctim = now,
			.st_atim = now,
			.st_mtim = now,
		},
		.type = FS_SYMLINK,
		.f = { .len = 0, .buf = NULL }
	};

	snprintf(ret.name, sizeof(ret.name), "%s", name);

	return ret;
}

static struct fs_entry fs_root;

const char *next_path(const char *path, char *buf) {
	for (; (*path != '/') && (*path != '\0'); *buf++ = *path++);
	*buf = '\0';

	if (*path == '/') path++;

	return path;
}

struct fs_entry *fs_add_entry(struct fs_entry *dir, struct fs_entry *en) {
	ASSERT(dir->type == FS_DIR);
	struct fs_entry *ret = NULL;
	char *name = en->name;
	HASH_FIND_STR(dir->dir.direntries, name, ret);

	if (ret) HASH_DEL(dir->dir.direntries, ret);

	HASH_ADD_STR(dir->dir.direntries, name, en);
	return ret;
}

struct fs_entry *fs_get_entry(struct fs_entry *dir, const char *name) {
	ASSERT(dir->type == FS_DIR);
	struct fs_entry *ret;
	HASH_FIND_STR(dir->dir.direntries, name, ret);

	return ret;
}

struct fs_entry *fs_add_dir(struct fs_entry *dir, char *name, uid_t uid, gid_t
		gid, mode_t mode) {
	struct fs_entry *newdir = XMALLOC(sizeof(*newdir));
	*newdir = fs_new_dir(name, uid, gid, mode);
	fs_add_entry(dir, newdir);

	return newdir;
}

struct fs_entry *fs_find_entry(struct fs_entry *root, const char *path) {
	ASSERT(root->type == FS_DIR);

	char pathseg[MAX_PATH_SEG + 1] = {0};
	struct fs_entry *cur = root;

	if (!strcmp(path, "/"))
		return cur;

	if (*path == '/')
		path++;

	do {
		DEBUG_LOG("Find entry path '%s'\n", path);
		path = next_path(path, pathseg);

		cur = fs_get_entry(cur, pathseg);
		DEBUG_LOG("Find entry pathseg, path, cur '%s' '%s' '%p'\n",
				pathseg, path, cur);
		if (!cur)
			return NULL;

	} while (*path);

	DEBUG_LOG("Found entry '%s'\n", cur->name);

	return cur;
}

struct fs_entry *fs_delete_entry(struct fs_entry *dir, struct fs_entry *en) {
	ASSERT(dir->type == FS_DIR);

	HASH_DEL(dir->dir.direntries, en);

	return dir;
}

struct fs_entry *fs_find_parent(struct fs_entry *root, const char *path) {
	struct fs_entry *ret = NULL;
	char *tpath = strdup(path);
	ASSERT(tpath);

	struct fs_entry *dir = NULL;

	char *dirp = dirname(tpath);
	if (!strcmp(dirp, "."))
		dir = root;
	else
		dir = fs_find_entry(root, dirp);

	if (dir && dir->type == FS_DIR) ret = dir;

	free(tpath); /* NODE: stdup uses malloc, not XMALLOC */
	return ret;
}

static inline void fs_set_filesz(struct fs_entry *en, size_t sz) {
	en->f.len = sz;
	en->st.st_size = sz;
}

static inline void fs_set_filebuf(struct fs_entry *en, char *ptr, size_t sz,
		size_t cap) {
	en->f.buf = ptr;
	en->f.cap = cap;
	fs_set_filesz(en, sz);
	en->st.st_blocks = (cap + 511) / 512;
}

void fs_resize_file(struct fs_entry *en, size_t newlen) {
	struct fs_file *fl = &en->f;
	size_t newcap = fl->cap;
	char *ptr = fl->buf;

	if (newlen > fl->cap) {
		newcap = 4 * fl->cap / 3 < newlen ? newlen : 4 * fl->cap / 3;
		ptr = fl->buf ? XREALLOC(fl->buf, newcap) : XMALLOC(newcap);
		ASSERT(ptr);
		memset(ptr + fl->cap, 0, newcap - fl->cap);
	}

	fs_set_filebuf(en, ptr, newlen, newcap);
}

struct fs_entry *fs_new() {
	uid_t uid = getuid();
	gid_t gid = getgid();

	fs_root = fs_new_dir("root", uid, gid, 0755);
	// struct fs_entry *cur = &fs_root;
	// struct fs_entry *dir1 = fs_add_dir(cur, "test", uid, gid, 0755);
	// struct fs_entry *dir2 = fs_add_dir(cur, "test1", uid, gid, 0755);
	// struct fs_entry *dir11 = fs_add_dir(dir1, "dir1_1", uid, gid, 0755);
	// fs_add_dir(dir1, "dir1_2", uid, gid, 0755);
	// fs_add_dir(dir1, "dir1_3", uid, gid, 0755);
	// fs_add_dir(dir1, "dir1_4", uid, gid, 0755);
    //
	// fs_add_dir(dir2, "dir2_1", uid, gid, 0755);
	// fs_add_dir(dir2, "dir2_2", uid, gid, 0755);
	// fs_add_dir(dir2, "dir2_3", uid, gid, 0755);
	// fs_add_dir(dir2, "dir2_4", uid, gid, 0755);
    //
	// fs_add_dir(dir11, "dir3_1", uid, gid, 0755);
	// fs_add_dir(dir11, "dir3_2", uid, gid, 0755);
	// fs_add_dir(dir11, "dir3_3", uid, gid, 0755);
	// fs_add_dir(dir11, "dir3_4", uid, gid, 0755);

	return &fs_root;
}

void *fs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
	(void)conn;
	(void)cfg;

	return fs_new();
}

void fs_free_entry(struct fs_entry *en) {
	switch (en->type) {
		case FS_FILE:
		case FS_SYMLINK:
			XFREE(en->f.buf);
			en->f.buf = NULL;
			en->f.len = en->f.cap = 0;
			break;

		case FS_DIR:

			{
				struct fs_entry *cur, *t;
				HASH_ITER(hh, en->dir.direntries, cur, t) {
					HASH_DEL(en->dir.direntries, cur);
					fs_free_entry(cur);
					XFREE(cur);
				}
			}
			break;

		default:
			fprintf(stderr, "Unkown filetype %d\n", en->type);
			ASSERT(0);

	}
}

void fs_destroy(void *private_data) {
	(void)private_data;

	fs_free_entry(&fs_root);
}

int fs_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
	(void)fi;

	struct fs_entry *en = fs_find_entry(&fs_root, path);
	DEBUG_LOG("FS getattr path %p '%s'\n", en, path);

	if (!en)
		return -ENOENT;

	*st = en->st;

	return 0;
}

int fs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi,
		enum fuse_readdir_flags flags) {
	(void)offset;
	(void)fi;
	(void)flags;

	DEBUG_LOG("FS readdir path '%s'\n", path);

	filler(buffer, ".", NULL, 0, 0);
	filler(buffer, "..", NULL, 0, 0);

	struct fs_entry *dir = fs_find_entry(&fs_root, path);
	if (!dir || dir->type != FS_DIR)
		return -ENOENT;

	for (struct fs_entry *s = dir->dir.direntries; s != NULL; s = s->hh.next) {
		ASSERT(filler(buffer, s->name, NULL, 0, 0) != 1);
	}

	return 0;
}

int fs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	(void)fi;

	struct fs_entry *dir = fs_find_parent(&fs_root, path), *file = NULL;
	if (!dir)
		return -ENOENT;

	{
		char *tpath = strdup(path);
		ASSERT(tpath);

		char *filen = basename(tpath);
		DEBUG_LOG("Create '%s' '%s' '%s'\n", path, filen,
				dir->name);
		file = XMALLOC(sizeof(*file));
		ASSERT(file);
		*file = fs_new_file(filen, getuid(), getgid(), mode);

		free(tpath); /* NODE: stdup uses malloc, not XMALLOC */
	}

	fs_add_entry(dir, file);

	return 0;
}

int fs_write(const char *path, const char *buf, size_t sz, off_t off, struct
		fuse_file_info *fi) {
	(void)fi;

	struct fs_entry *en = fs_find_entry(&fs_root, path);

	if (!en)
		return -ENOENT;

	if (en->type != FS_FILE)
		return -EBADF;

	if (en->f.len < off + sz)
		fs_resize_file(en, off + sz);

	memcpy(en->f.buf + off, buf, sz);

	struct timespec now = get_time();
	en->st.st_atim = now;
	en->st.st_mtim = now;

	DEBUG_LOG("Write '%s' buf: %p, sz: %zu, off: %zd\n",
			path, buf, sz, off);

	return sz;
}

int fs_read(const char *path, char *buf, size_t sz, off_t off,
		struct fuse_file_info *fi) {
	(void)fi;

	ASSERT(off >= 0);

	struct fs_entry *en = fs_find_entry(&fs_root, path);

	if (!en)
		return -ENOENT;

	if (en->type != FS_FILE)
		return -EBADF;

	struct fs_file *fl = &en->f;

	ASSERT(off >= 0);
	if ((size_t)off > fl->len)
		return EOF;

	if (fl->len < off + sz) {
		sz = fl->len - off;
	}

	memcpy(buf, fl->buf + off, sz);

	en->st.st_atim = get_time();

	return sz;
}

int fs_unlink(const char *path) {
	struct fs_entry *dir = fs_find_parent(&fs_root, path);
	if (!dir)
		return -ENOENT;

	char *pathcopy = strdup(path);
	ASSERT(pathcopy);
	char *fname = basename(pathcopy);

	struct fs_entry *en = fs_get_entry(dir, fname);
	free(pathcopy);
	if (!en)
		return -ENOENT;

	if (en->type != FS_FILE && en->type != FS_SYMLINK)
		return -EBADF;

	char *ptr = en->f.buf;
	en->f.buf = NULL;
	en->f.len = 0;
	en->st.st_size = 0;

	XFREE(ptr);

	fs_delete_entry(dir, en);
	XFREE(en);

	return 0;
}

int fs_rmdir(const char *path) {
	struct fs_entry *dir = fs_find_parent(&fs_root, path);
	if (!dir)
		return -ENOENT;

	char *pathcopy = strdup(path);
	ASSERT(pathcopy);
	char *fname = basename(pathcopy);

	struct fs_entry *en = fs_get_entry(dir, fname);
	free(pathcopy); /* NOTE: stdup uses malloc, not XMALLOC */
	if (!en)
		return -ENOENT;

	if (en->type != FS_DIR)
		return -ENOTDIR;

	fs_delete_entry(dir, en);
	XFREE(en);

	return 0;
}

int fs_mkdir(const char *path, mode_t mode) {
	mode |= S_IFDIR;

	struct fs_entry *dir = fs_find_parent(&fs_root, path);
	if (!dir)
		return -ENOENT;

	if (dir->type != FS_DIR)
		return -ENOTDIR;

	char *pathcopy = strdup(path);
	ASSERT(pathcopy);
	char *fname = basename(pathcopy);

	struct fs_entry *en = XMALLOC(sizeof(*en));
	ASSERT(en);
	*en = fs_new_dir(fname, getuid(), getgid(), mode);
	free(pathcopy); /* NOTE: stdup uses malloc, not XMALLOC */

	fs_add_entry(dir, en);

	DEBUG_LOG("Mkdir '%s', %o, %p, %p\n", path, mode, dir, en);

	return 0;
}

int fs_truncate(const char *path, off_t len, struct fuse_file_info *fi) {
	(void)fi;

	ASSERT(len >= 0);

	struct fs_entry *en = fs_find_entry(&fs_root, path);

	if (!en)
		return -ENOENT;

	if (en->type != FS_FILE)
		return -EBADF;

	if (en->f.len > (size_t)len)
		fs_set_filesz(en, len);
	else if (en->f.len < (size_t)len)
		fs_resize_file(en, len);

	struct timespec now = get_time();
	en->st.st_atim = now;
	en->st.st_mtim = now;

	return 0;
}

int fs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
	(void)fi;

	struct fs_entry *en = fs_find_entry(&fs_root, path);

	if (!en)
		return -ENOENT;

	en->st.st_mode = mode;

	return 0;
}

int fs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
	(void)fi;

	struct fs_entry *en = fs_find_entry(&fs_root, path);

	if (!en)
		return -ENOENT;

	en->st.st_uid = uid;
	en->st.st_gid = gid;

	return 0;
}

int fs_symlink(const char *target, const char *path) {
	struct fs_entry *dir = fs_find_parent(&fs_root, path), *file = NULL;
	if (!dir)
		return -ENOENT;

	{
		char *tpath = strdup(path);
		ASSERT(tpath);

		char *filen = basename(tpath);
		DEBUG_LOG("Symlink '%s' '%s' '%s'\n", path, filen,
				dir->name);
		file = XMALLOC(sizeof(*file));
		ASSERT(file);
		*file = fs_new_symlink(filen, getuid(), getgid(), 0755);

		free(tpath); /* NOTE: stdup uses malloc, not XMALLOC */
	}

	size_t targetlen = strlen(target) + 1;
	file->f.buf = strdup(target);
	file->f.len = file->f.cap = targetlen;

	fs_add_entry(dir, file);

	return 0;
}

int fs_readlink(const char *path, char *buf, size_t bufsz) {
	struct fs_entry *en = fs_find_entry(&fs_root, path);
	if (!en)
		return -ENOENT;

	if (en->type != FS_SYMLINK)
		return -EBADF;

	snprintf(buf, bufsz, "%s", en->f.buf);

	return 0;
}

int fs_utimens(const char *path, const struct timespec tv[2],
		struct fuse_file_info *fi) {
	(void)fi;

	struct fs_entry *en = fs_find_entry(&fs_root, path);
	if (!en)
		return -ENOENT;

	en->st.st_atim = en->st.st_mtim = *tv;

	return 0;
}

// int fs_fallocate(const char *path, int mode, off_t offset, off_t len,
// 		struct fuse_file_info *fi) {
// 	(void)fi;
//
// 	struct fs_entry *en = fs_find_entry(&fs_root, path);
// 	if (!en)
// 		return -ENOENT;
//
// 	if (en->type != FS_FILE)
// 		return -EBADF;
//
// 	if (!mode) {
// 	} else if (mode & FALLOC_FL_KEEP_SIZE) {
// 	}
//
// 	return -EPERM;
// }
