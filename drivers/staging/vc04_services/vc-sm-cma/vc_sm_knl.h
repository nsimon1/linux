/* SPDX-License-Identifier: GPL-2.0 */

/*
 * VideoCore Shared Memory CMA allocator
 *
 * Copyright: 2018, Raspberry Pi (Trading) Ltd
 *
 */

#ifndef __VC_SM_KNL_H__INCLUDED__
#define __VC_SM_KNL_H__INCLUDED__

#if !defined(__KERNEL__)
#error "This interface is for kernel use only..."
#endif

/* Type of memory to be locked (ie mapped) */
enum vc_sm_lock_cache_mode {
	VC_SM_LOCK_CACHED,
	VC_SM_LOCK_NON_CACHED,
};

/* Cache functions */
#define VCSM_CACHE_OP_INV       0x01
#define VCSM_CACHE_OP_CLEAN     0x02
#define VCSM_CACHE_OP_FLUSH     0x03

/* Request to allocate memory (HOST->VC) */
struct vc_sm_cma_knl_alloc_t {
	/* type of memory to allocate */
	bool cached;
	/* byte amount of data to allocate per unit */
	u32 base_unit;
	/* number of unit to allocate */
	u32 num_unit;
};

/* Allocate a shared memory handle and block. */
int vc_sm_cma_alloc(struct vc_sm_cma_knl_alloc_t *alloc, int *handle);

/* Free a previously allocated shared memory handle and block. */
int vc_sm_cma_free(int handle);

/* Lock a memory handle for use by kernel. */
int vc_sm_cma_lock(int handle, enum vc_sm_lock_cache_mode mode,
		   unsigned long *data);

/* Unlock a memory handle in use by kernel. */
int vc_sm_cma_unlock(int handle, int flush, int no_vc_unlock);

/* Get an internal resource handle mapped from the external one. */
int vc_sm_cma_int_handle(int handle);

/* Map a shared memory region for use by kernel. */
int vc_sm_cma_map(int handle, unsigned int sm_addr,
		  enum vc_sm_lock_cache_mode mode, unsigned long *data);

/* Import a block of memory into the GPU space. */
int vc_sm_cma_import_dmabuf(struct dma_buf *dmabuf, int *handle);

/* Export a shared memory handle as a dmabuf */
int vc_sm_cma_export_dmabuf(int handle, struct dma_buf **dmabuf);

#endif /* __VC_SM_KNL_H__INCLUDED__ */
