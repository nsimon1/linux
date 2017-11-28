/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright 2018 Raspberry Pi (Trading) Ltd.  All rights reserved.
 *
 * Based on vmcs_sm_ioctl.h Copyright Broadcom Corporation.
 */

#ifndef __VC_SM_CMA_IOCTL_H
#define __VC_SM_CMA_IOCTL_H

/* ---- Include Files ---------------------------------------------------- */

#if defined(__KERNEL__)
#include <linux/types.h>	/* Needed for standard types */
#else
#include <stdint.h>
#endif

#include <linux/ioctl.h>

/* ---- Constants and Types ---------------------------------------------- */

#define VC_SM_CMA_RESOURCE_NAME               32
#define VC_SM_CMA_RESOURCE_NAME_DEFAULT       "sm-host-resource"

/* Type define used to create unique IOCTL number */
#define VC_SM_CMA_MAGIC_TYPE                  'J'

/* IOCTL commands on /dev/vc-sm-cma */
enum vc_sm_cma_cmd_e {
	VC_SM_CMA_CMD_ALLOC = 0x5A,	/* Start at 0x5A arbitrarily */
	VC_SM_CMA_CMD_FLUSH,
	VC_SM_CMA_CMD_INVALID,

	VC_SM_CMA_CMD_MAPPED_VC_HDL_FROM_HDL,
	VC_SM_CMA_CMD_MAPPED_VC_ADDR_FROM_HDL,

	VC_SM_CMA_CMD_VC_WALK_ALLOC,
	VC_SM_CMA_CMD_HOST_WALK_MAP,
	VC_SM_CMA_CMD_HOST_WALK_PID_ALLOC,
	VC_SM_CMA_CMD_HOST_WALK_PID_MAP,

	VC_SM_CMA_CMD_CLEAN_INVALID,
	VC_SM_CMA_CMD_CLEAN_INVALID2,

	VC_SM_CMA_CMD_IMPORT_DMABUF,

	VC_SM_CMA_CMD_GET_VERSION,

	VC_SM_CMA_CMD_LAST	/* Do not delete */
};

/* Cache type supported, conveniently matches the user space definition in
 * user-vcsm.h.
 */
enum vc_sm_cma_cache_e {
	VC_SM_CMA_CACHE_NONE,
	VC_SM_CMA_CACHE_HOST,
	VC_SM_CMA_CACHE_VC,
	VC_SM_CMA_CACHE_BOTH,
};

/* IOCTL Data structures */
struct vc_sm_cma_ioctl_alloc {
	/* user -> kernel */
	unsigned int size;
	unsigned int num;
	enum vc_sm_cma_cache_e cached;
	char name[VC_SM_CMA_RESOURCE_NAME];

	/* kernel -> user */
	unsigned int handle;
	/* unsigned int base_addr; */
};

struct vc_sm_cma_ioctl_alloc_share {
	/* user -> kernel */
	unsigned int handle;
	unsigned int size;
};

struct vc_sm_cma_ioctl_map {
	/* user -> kernel */
	/* and kernel -> user */
	int fd;
	unsigned int handle;
	unsigned int addr;

	/* kernel -> user */
	unsigned int size;
};

struct vc_sm_cma_ioctl_walk {
	/* user -> kernel */
	unsigned int pid;
};

struct vc_sm_cma_ioctl_cache {
	/* user -> kernel */
	unsigned int handle;
	unsigned int addr;
	unsigned int size;
};

struct vc_sm_cma_ioctl_clean_invalid {
	/* user -> kernel */
	struct {
		unsigned int cmd;
		unsigned int handle;
		unsigned int addr;
		unsigned int size;
	} s[8];
};

struct vc_sm_cma_ioctl_clean_invalid2 {
	uint8_t op_count;
	uint8_t zero[3];
	struct vc_sm_cma_ioctl_clean_invalid_block {
		uint16_t invalidate_mode;
		uint16_t block_count;
		void     *start_address;
		uint32_t block_size;
		uint32_t inter_block_stride;
	} s[0];
};

struct vc_sm_cma_ioctl_import_dmabuf {
	/* user -> kernel */
	int dmabuf_fd;
	enum vc_sm_cma_cache_e cached;
	char name[VC_SM_CMA_RESOURCE_NAME];

	/* kernel -> user */
	int handle;
	unsigned int size;
};

/* IOCTL numbers */
#define VC_SM_CMA_IOCTL_MEM_ALLOC\
	_IOR(VC_SM_CMA_MAGIC_TYPE, VC_SM_CMA_CMD_ALLOC,\
	 struct vc_sm_cma_ioctl_alloc)
#define VC_SM_CMA_IOCTL_MEM_FLUSH\
	_IOR(VC_SM_CMA_MAGIC_TYPE, VC_SM_CMA_CMD_FLUSH,\
	 struct vc_sm_cma_ioctl_cache)
#define VC_SM_CMA_IOCTL_MEM_INVALID\
	_IOR(VC_SM_CMA_MAGIC_TYPE, VC_SM_CMA_CMD_INVALID,\
	 struct vc_sm_cma_ioctl_cache)
#define VC_SM_CMA_IOCTL_MEM_CLEAN_INVALID\
	_IOR(VC_SM_CMA_MAGIC_TYPE, VC_SM_CMA_CMD_CLEAN_INVALID,\
	 struct vc_sm_cma_ioctl_clean_invalid)
#define VC_SM_CMA_IOCTL_MEM_CLEAN_INVALID2\
	_IOR(VC_SM_CMA_MAGIC_TYPE, VC_SM_CMA_CMD_CLEAN_INVALID2,\
	 struct vc_sm_cma_ioctl_clean_invalid2)

#define VC_SM_CMA_IOCTL_MAP_VC_HDL_FR_HDL\
	_IOR(VC_SM_CMA_MAGIC_TYPE, VC_SM_CMA_CMD_MAPPED_VC_HDL_FROM_HDL,\
	 struct vc_sm_cma_ioctl_map)
#define VC_SM_CMA_IOCTL_MAP_VC_ADDR_FR_HDL\
	_IOR(VC_SM_CMA_MAGIC_TYPE, VC_SM_CMA_CMD_MAPPED_VC_ADDR_FROM_HDL,\
	 struct vc_sm_cma_ioctl_map)

#define VC_SM_CMA_IOCTL_VC_WALK_ALLOC\
	_IO(VC_SM_CMA_MAGIC_TYPE, VC_SM_CMA_CMD_VC_WALK_ALLOC)
#define VC_SM_CMA_IOCTL_HOST_WALK_MAP\
	_IO(VC_SM_CMA_MAGIC_TYPE, VC_SM_CMA_CMD_HOST_WALK_MAP)
#define VC_SM_CMA_IOCTL_HOST_WALK_PID_ALLOC\
	_IOR(VC_SM_CMA_MAGIC_TYPE, VC_SM_CMA_CMD_HOST_WALK_PID_ALLOC,\
	 struct vc_sm_cma_ioctl_walk)
#define VC_SM_CMA_IOCTL_HOST_WALK_PID_MAP\
	_IOR(VC_SM_CMA_MAGIC_TYPE, VC_SM_CMA_CMD_HOST_WALK_PID_MAP,\
	 struct vc_sm_cma_ioctl_walk)

#define VC_SM_CMA_IOCTL_MEM_IMPORT_DMABUF\
	_IOR(VC_SM_CMA_MAGIC_TYPE, VC_SM_CMA_CMD_IMPORT_DMABUF,\
	 struct vc_sm_cma_ioctl_import_dmabuf)

#endif /* __VC_SM_CMA_IOCTL_H */
