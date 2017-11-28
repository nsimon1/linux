/* SPDX-License-Identifier: GPL-2.0 */

/*
 * VideoCore Shared Memory driver using CMA.
 *
 * Copyright: 2018, Raspberry Pi (Trading) Ltd
 *
 */

#ifndef VC_SM_H
#define VC_SM_H

#include <linux/device.h>
#include <linux/dma-direction.h>
#include <linux/kref.h>
#include <linux/mm_types.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/shrinker.h>
#include <linux/types.h>
#include <linux/miscdevice.h>

/* Statistics tracked per resource and globally. */
enum sm_stats_t {
	/* Attempt. */
	ALLOC,
	FREE,
	LOCK,
	UNLOCK,
	MAP,
	FLUSH,
	INVALID,
	IMPORT,
	EXPORT,

	END_ATTEMPT,

	/* Failure. */
	ALLOC_FAIL,
	FREE_FAIL,
	LOCK_FAIL,
	UNLOCK_FAIL,
	MAP_FAIL,
	FLUSH_FAIL,
	INVALID_FAIL,
	IMPORT_FAIL,
	EXPORT_FAIL,

	END_ALL,

};

/**
 * struct vc_sm_heap - represents a heap in the system
 * @node:		rb node to put the heap on the device's tree of heaps
 * @dev:		back pointer to the vc_sm_device
 * @type:		type of heap
 * @ops:		ops struct as above
 * @flags:		flags
 * @id:			id of heap, also indicates priority of this heap when
 *			allocating.  These are specified by platform data and
 *			MUST be unique
 * @name:		used for debugging
 * @shrinker:		a shrinker for the heap
 * @free_list:		free list head if deferred free is used
 * @free_list_size	size of the deferred free list in bytes
 * @lock:		protects the free list
 * @waitqueue:		queue to wait on from deferred free thread
 * @task:		task struct of deferred free thread
 * @debug_show:		called when heap debug file is read to add any
 *			heap specific debug info to output
 *
 * Represents a pool of memory from which buffers can be made.  In some
 * systems the only heap is regular system memory allocated via vmalloc.
 * On others, some blocks might require large physically contiguous buffers
 * that are allocated from a specially reserved heap.
 */
struct vc_sm_heap {
	struct plist_node node;
	struct vc_sm_device *dev;
	struct vc_sm_heap_ops *ops;
	unsigned long flags;
	unsigned int id;
	const char *name;
	struct shrinker shrinker;
	struct list_head free_list;
	size_t free_list_size;
	spinlock_t free_lock;
	wait_queue_head_t waitqueue;
	struct task_struct *task;

	int (*debug_show)(struct vc_sm_heap *heap, struct seq_file *, void *);
};

#define VC_SM_MAX_NAME_LEN 32

enum vc_sm_vpu_mapping_state {
	VPU_NOT_MAPPED,
	VPU_MAPPED,
	VPU_UNMAPPING
};

struct vc_sm_buffer {
	struct list_head global_buffer_list;	/* Global list of buffers. */

	unsigned long flags;
	unsigned long private_flags;
	size_t size;
	void *priv_virt;
	struct mutex lock;
	int kmap_cnt;
	void *vaddr;
	struct sg_table *sg_table;
	struct list_head attachments;

	char name[VC_SM_MAX_NAME_LEN];
	u32 ref_count;	/* Ref count for this buffer. */
	enum vc_sm_vpu_mapping_state vpu_state;
	int vpu_allocated;	/*
				 * The VPU made this allocation. Release the
				 * local dma_buf when the VPU releases the
				 * resource.
				 */

	u32 vc_handle;	/* VideoCore handle for this buffer */

	pid_t pid;		/* PID owning that resource. */
	u32 lock_count;	/* Lock count for this resource. */

	void *res_base_mem;	/* Resource base memory address. */

	struct cma *cma_heap;

	/* DMABUF related fields */
	struct dma_buf *import_dma_buf;
	struct dma_buf *dma_buf;
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
	dma_addr_t dma_addr;

	struct vc_sm_privdata_t *private;
	bool map;		/* whether to map pages up front */
};

void vc_sm_buffer_destroy(struct vc_sm_buffer *buffer);

/**
 * struct vc_sm_device - the metadata of the vc_sm device node
 * @dev:		the actual misc device
 * @buffers:		an rb tree of all the existing buffers
 * @buffer_lock:	lock protecting the tree of buffers
 * @lock:		rwsem protecting the tree of heaps and clients
 */
struct vc_sm_device {
	struct miscdevice dev;
	struct rb_root buffers;
	struct mutex buffer_lock;
	struct rw_semaphore lock;
	struct plist_head heaps;
	struct dentry *debug_root;
	int heap_cnt;
};

/**
 * struct vc_sm_heap_ops - ops to operate on a given heap
 * @allocate:		allocate memory
 * @free:		free memory
 * @map_kernel		map memory to the kernel
 * @unmap_kernel	unmap memory to the kernel
 * @map_user		map memory to userspace
 *
 * allocate, phys, and map_user return 0 on success, -errno on error.
 * map_dma and map_kernel return pointer on success, ERR_PTR on
 * error.
 */
struct vc_sm_heap_ops {
	int (*allocate)(struct vc_sm_heap *heap,
			struct vc_sm_buffer *buffer, unsigned long len,
			unsigned long flags);
	void (*free)(struct vc_sm_buffer *buffer);
	void * (*map_kernel)(struct vc_sm_heap *heap, struct vc_sm_buffer *buffer);
	void (*unmap_kernel)(struct vc_sm_heap *heap, struct vc_sm_buffer *buffer);
	int (*map_user)(struct vc_sm_heap *mapper, struct vc_sm_buffer *buffer,
			struct vm_area_struct *vma);
	int (*shrink)(struct vc_sm_heap *heap, gfp_t gfp_mask, int nr_to_scan);
};

/**
 * vc_sm_buffer_fault_user_mappings - fault in user mappings of this buffer
 * @buffer:		buffer
 *
 * indicates whether userspace mappings of this buffer will be faulted
 * in, this can affect how buffers are allocated from the heap.
 */
bool vc_sm_buffer_fault_user_mappings(struct vc_sm_buffer *buffer);

/**
 * vc_sm_device_add_heap - adds a heap to the vc_sm device
 * @heap:		the heap to add
 */
void vc_sm_device_add_heap(struct vc_sm_heap *heap);

/**
 * some helpers for common operations on buffers using the sg_table
 * and vaddr fields
 */
//void *vc_sm_heap_map_kernel(struct vc_sm_heap *heap, struct vc_sm_buffer *buffer);
//void vc_sm_heap_unmap_kernel(struct vc_sm_heap *heap, struct vc_sm_buffer *buffer);
//int vc_sm_heap_map_user(struct vc_sm_heap *heap, struct vc_sm_buffer *buffer,
			//struct vm_area_struct *vma);
//int vc_sm_heap_buffer_zero(struct vc_sm_buffer *buffer);
//int vc_sm_heap_pages_zero(struct page *page, size_t size, pgprot_t pgprot);

//static long vc_sm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

int vc_sm_query_heaps(struct vc_sm_heap *query);

#endif
