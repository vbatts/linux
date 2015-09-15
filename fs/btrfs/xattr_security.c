/*
 * Copyright (C) 2015 Red Hat.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <linux/string.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/slab.h>
#include "xattr.h"

static size_t
btrfs_xattr_security_list(struct dentry *dentry, char *list, size_t list_size,
		const char *name, size_t name_len, int type)
{
	const size_t total_len = XATTR_SECURITY_PREFIX_LEN + name_len + 1;


	if (list && total_len <= list_size) {
		memcpy(list, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN);
		memcpy(list+XATTR_SECURITY_PREFIX_LEN, name, name_len);
		list[XATTR_SECURITY_PREFIX_LEN + name_len] = '\0';
	}
	return total_len;
}

static int
btrfs_xattr_security_get(struct dentry *dentry, const char *name,
		       void *buffer, size_t size, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return btrfs_getxattr(d_inode(dentry), name, buffer, size);
}

static int
btrfs_xattr_security_set(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return btrfs_setxattr(d_inode(dentry), name, value, size, flags);
}

const struct xattr_handler btrfs_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.list	= btrfs_xattr_security_list,
	.get	= btrfs_xattr_security_get,
	.set	= btrfs_xattr_security_set,
};
