/* SPDX-License-Identifier: GPL-2.0 */

/*
 * VideoCore Shared Memory driver using CMA.
 *
 * Copyright: 2018, Raspberry Pi (Trading) Ltd
 * Dave Stevenson <dave.stevenson@raspberrypi.org>
 *
 * Based on vmcs_sm driver from Broadcom Corporation for some API,
 * and taking some code for CMA/dmabuf handling from the Android Ion
 * driver (Google/Linaro).
 *
 */

/* ---- Include Files ----------------------------------------------------- */

#include <linux/cdev.h>
#include <linux/broadcom/vc_mem.h>
#include <linux/device.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/dma-buf.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/hugetlb.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pfn.h>
#include <linux/proc_fs.h>
#include <linux/pagemap.h>
#include <linux/refcount.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <asm/cacheflush.h>

#include "vchiq_connected.h"
#include "vc_vchi_sm.h"

#include "vc_sm.h"
#include "vc_sm_cma.h"
#include "vc_sm_knl.h"
#include <linux/broadcom/vc_sm_cma_ioctl.h>

/* ---- Private Constants and Types --------------------------------------- */

#define TEMPORARILY_DISABLED 0	//FIXME: Remove once all converted

#define DEVICE_NAME		"vcsm-cma"
#define DRIVER_NAME		"bcm2835-vcsm-cma"
#define DEVICE_MINOR		0

#define VC_SM_RESOURCE_NAME_DEFAULT       "sm-host-resource"

#define VC_SM_DIR_ROOT_NAME	"vcsm-cma"
#define VC_SM_DIR_ALLOC_NAME	"alloc"
#define VC_SM_STATE		"state"
#define VC_SM_STATS		"statistics"
#define VC_SM_RESOURCES		"resources"
#define VC_SM_DEBUG		"debug"
#define VC_SM_WRITE_BUF_SIZE	128

static const char *const sm_stats_human_read[] = {
	"Alloc",
	"Free",
	"Lock",
	"Unlock",
	"Map",
	"Cache Flush",
	"Cache Invalidate",
	"Import",
};

/* Private file data associated with each opened device. */
struct vc_sm_privdata_t {
	pid_t pid;                      /* PID of creator. */

	int restart_sys;		/* Tracks restart on interrupt. */
	enum vc_sm_msg_type int_action;	/* Interrupted action. */
	u32 int_trans_id;		/* Interrupted transaction. */
};

typedef int (*VC_SM_SHOW) (struct seq_file *s, void *v);
struct sm_pde_t {
	VC_SM_SHOW show;          /* Debug fs function hookup. */
	struct dentry *dir_entry; /* Debug fs directory entry. */
	void *priv_data;          /* Private data */

};

/* Global state information. */
struct sm_state_t {
	struct platform_device *pdev;

	struct miscdevice dev;
	struct sm_instance *sm_handle;	/* Handle for videocore service. */
	struct cma *cma_heap;

	struct mutex map_lock;          /* Global map lock. */
	struct list_head buffer_list;	/* List of buffer. */

	struct vc_sm_privdata_t *data_knl;  /* Kernel internal data tracking. */
	struct vc_sm_privdata_t *vpu_allocs; /* All allocations from the VPU */
	struct dentry *dir_root;	/* Debug fs entries root. */
	struct sm_pde_t dir_state;	/* Debug fs entries state sub-tree. */

	bool require_released_callback;	/* VPU will send a released msg when it
					 * has finished with a resource.
					 */
	u32 int_trans_id;		/* Interrupted transaction. */
};

/* ---- Private Variables ----------------------------------------------- */

static struct sm_state_t *sm_state;
static int sm_inited;

#if TEMPORARILY_DISABLED
typedef void cache_flush_op_fn(const void *, const void *);

#if defined(CONFIG_CPU_CACHE_V7)
extern cache_flush_op_fn v7_dma_inv_range;
extern cache_flush_op_fn v7_dma_clean_range;
static cache_flush_op_fn * const flushops[4] = {
	0,
	v7_dma_inv_range,
	v7_dma_clean_range,
	v7_dma_flush_range,
};
#elif defined(CONFIG_CPU_CACHE_V6)
extern cache_flush_op_fn v6_dma_inv_range;
extern cache_flush_op_fn v6_dma_clean_range;
static cache_flush_op_fn * const flushops[4] = {
	0,
	v6_dma_inv_range,
	v6_dma_clean_range,
	v6_dma_flush_range,
};
#else
#error Unknown cache config
#endif
#endif
/* ---- Private Function Prototypes -------------------------------------- */

/* ---- Private Functions ------------------------------------------------ */

static int vc_sm_cma_seq_file_show(struct seq_file *s, void *v)
{
	struct sm_pde_t *sm_pde;

	sm_pde = (struct sm_pde_t *)(s->private);

	if (sm_pde && sm_pde->show)
		sm_pde->show(s, v);

	return 0;
}

static int vc_sm_cma_single_open(struct inode *inode, struct file *file)
{
	return single_open(file, vc_sm_cma_seq_file_show, inode->i_private);
}

static const struct file_operations vc_sm_cma_debug_fs_fops = {
	.open = vc_sm_cma_single_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int vc_sm_cma_global_state_show(struct seq_file *s, void *v)
{
	struct vc_sm_buffer *resource = NULL;
	int resource_count = 0;

	if (!sm_state)
		return 0;

	seq_printf(s, "\nVC-ServiceHandle     0x%x\n",
		   (unsigned int)sm_state->sm_handle);

	/* Log all applicable mapping(s). */

	mutex_lock(&sm_state->map_lock);
	seq_puts(s, "\nResources\n");
	if (!list_empty(&sm_state->buffer_list)) {
		list_for_each_entry(resource, &sm_state->buffer_list,
				    global_buffer_list) {
			resource_count++;

			seq_printf(s, "\nResource                %p\n",
				   resource);
			seq_printf(s, "           NAME         %s\n",
				   resource->name);
			seq_printf(s, "           PID          %u\n",
				   resource->pid);
			seq_printf(s, "           RES_BASE_MEM %p\n",
				   resource->res_base_mem);
			seq_printf(s, "           SIZE         %d\n",
				   resource->size);
			seq_printf(s, "           DMABUF       %p\n",
				   resource->dma_buf);
			seq_printf(s, "           ATTACH       %p\n",
				   resource->attach);
			seq_printf(s, "           SG_TABLE     %p\n",
				   resource->sg_table);
			seq_printf(s, "           SGT          %p\n",
				   resource->sgt);
			seq_printf(s, "           DMA_ADDR     %pad\n",
				   &resource->dma_addr);
			seq_printf(s, "           VC_HANDLE     %08X\n",
				   resource->vc_handle);
			seq_printf(s, "           VC_MAPPING    %d\n",
				   resource->vpu_state);
			seq_printf(s, "           VPU_ALLOCATED %d\n",
				   resource->vpu_allocated);
		}
	}
	seq_printf(s, "\n\nTotal resource count:   %d\n\n", resource_count);

	mutex_unlock(&sm_state->map_lock);

	return 0;
}

/*
 * Adds a buffer to the private data list which tracks all the allocated
 * data.
 */
static void vc_sm_add_resource(struct vc_sm_privdata_t *privdata,
			       struct vc_sm_buffer *buffer)
{
	mutex_lock(&sm_state->map_lock);
	list_add(&buffer->global_buffer_list, &sm_state->buffer_list);
	mutex_unlock(&sm_state->map_lock);

	pr_debug("[%s]: added buffer %p (name %s, size %d)\n",
		 __func__, buffer, buffer->name, buffer->size);
}

static void vc_sm_clean_up_dmabuf(struct vc_sm_buffer *buffer)
{
	/* Handle cleaning up imported dmabufs */
	if (buffer->sgt) {
		dma_buf_unmap_attachment(buffer->attach, buffer->sgt,
					 DMA_BIDIRECTIONAL);
		buffer->sgt = NULL;
	}
	if (buffer->attach) {
		dma_buf_detach(buffer->dma_buf, buffer->attach);
		buffer->attach = NULL;
	}

	/* Release the dma_buf (whether ours or imported) */
	if (buffer->import_dma_buf) {
		dma_buf_put(buffer->import_dma_buf);
		buffer->import_dma_buf = NULL;
		buffer->dma_buf = NULL;
	} else if (buffer->dma_buf) {
		dma_buf_put(buffer->dma_buf);
		buffer->dma_buf = NULL;
	}
}

static void vc_sm_destroy_buffer(struct vc_sm_buffer *buffer)
{
	pr_debug("[%s]: freeing buffer %p (name %s, size %d)\n",
		 __func__, buffer, buffer->name, buffer->size);

	mutex_destroy(&buffer->lock);

	vc_sm_cma_buffer_free(buffer);

	kfree(buffer);
}

/*
 * Release a previously acquired buffer.
 * All refcounting is done via the dma buf object.
 */
static void vc_sm_release_resource(struct vc_sm_buffer *buffer, int force)
{
	mutex_lock(&sm_state->map_lock);
	mutex_lock(&buffer->lock);

	pr_debug("[%s]: buffer %p (name %s, size %d)\n",
		 __func__, buffer, buffer->name, buffer->size);

	if (buffer->vc_handle && buffer->vpu_state == VPU_MAPPED) {
		struct vc_sm_free_t free = {
			buffer->vc_handle, (uint32_t)buffer->res_base_mem
		};
		int status = vc_sm_vchi_free(sm_state->sm_handle, &free,
					     &sm_state->int_trans_id);
		if (status != 0 && status != -EINTR) {
			pr_err("[%s]: failed to free memory on videocore (status: %u, trans_id: %u)\n",
			       __func__, status, sm_state->int_trans_id);
		}

		if (sm_state->require_released_callback) {
			/* Need to wait for the VPU to confirm the free */

			/* Retain a reference on this until the VPU has released it */
			buffer->vpu_state = VPU_UNMAPPING;
			mutex_unlock(&buffer->lock);
			mutex_unlock(&sm_state->map_lock);
			return;
		}
		buffer->vpu_state = VPU_NOT_MAPPED;
		buffer->vc_handle = 0;
	}
	if (buffer->dma_buf) {
		/* Don't release dmabuf here - we await the release */
		pr_err("[%s]: release %p when dma_buf is still in use\n",
		       __func__, buffer);
		mutex_unlock(&buffer->lock);
		mutex_unlock(&sm_state->map_lock);
		return;
	}

	if (buffer->sg_table && !buffer->import_dma_buf) {
		/* Our own allocation that we need to dma_unmap_sg */
		dma_unmap_sg(&sm_state->pdev->dev, buffer->sg_table->sgl,
			     buffer->sg_table->nents, DMA_BIDIRECTIONAL);
	}

	/* Time to free the buffer. Start by removing it from the list */
	buffer->private = NULL;
	list_del(&buffer->global_buffer_list);

	mutex_unlock(&buffer->lock);
	mutex_unlock(&sm_state->map_lock);

	vc_sm_destroy_buffer(buffer);
}

/* Create support for private data tracking. */
static struct vc_sm_privdata_t *vc_sm_cma_create_priv_data(pid_t id)
{
	char alloc_name[32];
	struct vc_sm_privdata_t *file_data = NULL;

	/* Allocate private structure. */
	file_data = kzalloc(sizeof(*file_data), GFP_KERNEL);

	if (!file_data) {
		pr_err("[%s]: cannot allocate file data\n", __func__);
		return NULL;
	}

	snprintf(alloc_name, sizeof(alloc_name), "%d", id);

	file_data->pid = id;

	return file_data;
}

/*
 * Open the device.  Creates a private state to help track all allocation
 * associated with this device.
 */
static int vc_sm_cma_open(struct inode *inode, struct file *file)
{
	int ret = 0;

	/* Make sure the device was started properly. */
	if (!sm_state) {
		pr_err("[%s]: invalid device\n", __func__);
		return -EPERM;
	}

	file->private_data = vc_sm_cma_create_priv_data(current->tgid);
	if (!file->private_data) {
		pr_err("[%s]: failed to create data tracker\n", __func__);

		return -ENOMEM;
	}

	return ret;
}

/*
 * Close the vcsm-cma device.
 * All allocations are file descriptors to the dmabuf objects, so we will get the
 * clean up request on those as those are cleaned up.
 */
static int vc_sm_cma_release(struct inode *inode, struct file *file)
{
	struct vc_sm_privdata_t *file_data =
	    (struct vc_sm_privdata_t *)file->private_data;
	int ret = 0;

	/* Make sure the device was started properly. */
	if (!sm_state || !file_data) {
		pr_err("[%s]: invalid device\n", __func__);
		ret = -EPERM;
		goto out;
	}

	pr_debug("[%s]: using private data %p\n", __func__, file_data);

	/* Terminate the private data. */
	kfree(file_data);

out:
	return ret;
}

#if TEMPORARILY_DISABLED
/* Walks a VMA and clean each valid page from the cache */
static void vcsm_vma_cache_clean_page_range(unsigned long addr,
					    unsigned long end)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long pgd_next, pud_next, pmd_next;

	if (addr >= end)
		return;

	/* Walk PGD */
	pgd = pgd_offset(current->mm, addr);
	do {
		pgd_next = pgd_addr_end(addr, end);

		if (pgd_none(*pgd) || pgd_bad(*pgd))
			continue;

		/* Walk PUD */
		pud = pud_offset(pgd, addr);
		do {
			pud_next = pud_addr_end(addr, pgd_next);
			if (pud_none(*pud) || pud_bad(*pud))
				continue;

			/* Walk PMD */
			pmd = pmd_offset(pud, addr);
			do {
				pmd_next = pmd_addr_end(addr, pud_next);
				if (pmd_none(*pmd) || pmd_bad(*pmd))
					continue;

				/* Walk PTE */
				pte = pte_offset_map(pmd, addr);
				do {
					if (pte_none(*pte) ||
					    !pte_present(*pte))
						continue;

					/* Clean + invalidate */
					dmac_flush_range((const void *)addr,
							 (const void *)
							 (addr + PAGE_SIZE));

				} while (pte++, addr +=
					 PAGE_SIZE, addr != pmd_next);
				pte_unmap(pte);

			} while (pmd++, addr = pmd_next, addr != pud_next);

		} while (pud++, addr = pud_next, addr != pgd_next);
	} while (pgd++, addr = pgd_next, addr != end);
}
#endif

static void *vc_sm_buffer_kmap_get(struct vc_sm_buffer *buffer)
{
	void *vaddr;

	if (buffer->kmap_cnt) {
		buffer->kmap_cnt++;
		return buffer->vaddr;
	}
	vaddr = vc_sm_cma_map_kernel(buffer);
	if (WARN_ONCE(!vaddr,
		      "vcsm_cma_map_kernel should return ERR_PTR on error"))
		return ERR_PTR(-EINVAL);
	if (IS_ERR(vaddr))
		return vaddr;
	buffer->vaddr = vaddr;
	buffer->kmap_cnt++;
	return vaddr;
}

static void vc_sm_buffer_kmap_put(struct vc_sm_buffer *buffer)
{
	buffer->kmap_cnt--;
	if (!buffer->kmap_cnt) {
		//vc_sm_cma_unmap_kernel(buffer);
		buffer->vaddr = NULL;
	}
}

static struct sg_table *dup_sg_table(struct sg_table *table)
{
	struct sg_table *new_table;
	int ret, i;
	struct scatterlist *sg, *new_sg;

	new_table = kzalloc(sizeof(*new_table), GFP_KERNEL);
	if (!new_table)
		return ERR_PTR(-ENOMEM);

	ret = sg_alloc_table(new_table, table->nents, GFP_KERNEL);
	if (ret) {
		kfree(new_table);
		return ERR_PTR(-ENOMEM);
	}

	new_sg = new_table->sgl;
	for_each_sg(table->sgl, sg, table->nents, i) {
		memcpy(new_sg, sg, sizeof(*sg));
		sg->dma_address = 0;
		new_sg = sg_next(new_sg);
	}

	return new_table;
}

static void free_duped_table(struct sg_table *table)
{
	sg_free_table(table);
	kfree(table);
}

struct vc_sm_dma_buf_attachment {
	struct device *dev;
	struct sg_table *table;
	struct list_head list;
};

static int vc_sm_dma_buf_attach(struct dma_buf *dmabuf, struct device *dev,
				struct dma_buf_attachment *attachment)
{
	struct vc_sm_dma_buf_attachment *a;
	struct sg_table *table;
	struct vc_sm_buffer *res = dmabuf->priv;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	table = dup_sg_table(res->sg_table);
	if (IS_ERR(table)) {
		kfree(a);
		return -ENOMEM;
	}

	a->table = table;
	a->dev = dev;
	INIT_LIST_HEAD(&a->list);

	attachment->priv = a;

	mutex_lock(&res->lock);
	list_add(&a->list, &res->attachments);
	mutex_unlock(&res->lock);
	pr_debug("%s dmabuf %p attachment %p\n", __func__, dmabuf, attachment);

	return 0;
}

static void vc_sm_dma_buf_detatch(struct dma_buf *dmabuf,
				  struct dma_buf_attachment *attachment)
{
	struct vc_sm_dma_buf_attachment *a = attachment->priv;
	struct vc_sm_buffer *res = dmabuf->priv;

	pr_debug("%s dmabuf %p attachment %p\n", __func__, dmabuf, attachment);
	free_duped_table(a->table);
	mutex_lock(&res->lock);
	list_del(&a->list);
	mutex_unlock(&res->lock);

	kfree(a);
}

static struct sg_table *vc_sm_map_dma_buf(struct dma_buf_attachment *attachment,
					  enum dma_data_direction direction)
{
	struct vc_sm_dma_buf_attachment *a = attachment->priv;
	struct sg_table *table;

	table = a->table;

	if (!dma_map_sg(attachment->dev, table->sgl, table->nents,
			direction))
		return ERR_PTR(-ENOMEM);

	pr_debug("%s attachment %p\n", __func__, attachment);
	return table;
}

static void vc_sm_unmap_dma_buf(struct dma_buf_attachment *attachment,
				struct sg_table *table,
				enum dma_data_direction direction)
{
	pr_debug("%s attachment %p\n", __func__, attachment);
	dma_unmap_sg(attachment->dev, table->sgl, table->nents, direction);
}

static int vc_sm_dmabuf_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct vc_sm_buffer *res = dmabuf->priv;
	struct sg_table *table = res->sg_table;
	unsigned long addr = vma->vm_start;
	unsigned long offset = vma->vm_pgoff * PAGE_SIZE;
	struct scatterlist *sg;
	int i;
	int ret = 0;

	pr_debug("%s dmabuf %p, res %p, vm_start %08lX\n", __func__, dmabuf,
		 res, addr);
/*	FIXME: How do we handle caching
	if (res->res_cached == VMCS_SM_CACHE_HOST ||
	    res->res_cached == VMCS_SM_CACHE_BOTH)
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
*/
	mutex_lock(&res->lock);

	/* now map it to userspace */
	for_each_sg(table->sgl, sg, table->nents, i) {
		struct page *page = sg_page(sg);
		unsigned long remainder = vma->vm_end - addr;
		unsigned long len = sg->length;

		if (offset >= sg->length) {
			offset -= sg->length;
			continue;
		} else if (offset) {
			page += offset / PAGE_SIZE;
			len = sg->length - offset;
			offset = 0;
		}
		len = min(len, remainder);
		ret = remap_pfn_range(vma, addr, page_to_pfn(page), len,
				      vma->vm_page_prot);
		if (ret)
			break;
		addr += len;
		if (addr >= vma->vm_end)
			break;
	}
	mutex_unlock(&res->lock);

	if (ret)
		pr_err("%s: failure mapping buffer to userspace\n",
		       __func__);

	return ret;
}

static void vc_sm_dma_buf_release(struct dma_buf *dmabuf)
{
	struct vc_sm_buffer *buffer;

	if (!dmabuf)
		return;
	buffer = (struct vc_sm_buffer *)dmabuf->priv;
	pr_debug("%s dmabuf %p, buffer %p\n", __func__, dmabuf, buffer);

	/* Keep the CMA allocation, but release the dma_buf object. */
	vc_sm_clean_up_dmabuf(buffer);

	vc_sm_release_resource(buffer, 0);
}

static void *vc_sm_dma_buf_kmap(struct dma_buf *dmabuf, unsigned long offset)
{
	struct vc_sm_buffer *res = dmabuf->priv;

	return res->vaddr + offset * PAGE_SIZE;
}

static void vc_sm_dma_buf_kunmap(struct dma_buf *dmabuf, unsigned long offset,
				 void *ptr)
{
}

static int vc_sm_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
					  enum dma_data_direction direction)
{
	struct vc_sm_buffer *res;
	struct vc_sm_dma_buf_attachment *a;

	if (!dmabuf)
		return -EFAULT;

	res = dmabuf->priv;
	if (!res)
		return -EFAULT;

	mutex_lock(&res->lock);

	list_for_each_entry(a, &res->attachments, list) {
		dma_sync_sg_for_cpu(a->dev, a->table->sgl, a->table->nents,
				    direction);
	}
	mutex_unlock(&res->lock);

	return 0;
}

static int vc_sm_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
					enum dma_data_direction direction)
{
	struct vc_sm_buffer *res;
	struct vc_sm_dma_buf_attachment *a;

	if (!dmabuf)
		return -EFAULT;
	res = dmabuf->priv;
	if (!res)
		return -EFAULT;

	mutex_lock(&res->lock);
	vc_sm_buffer_kmap_put(res);

	list_for_each_entry(a, &res->attachments, list) {
		dma_sync_sg_for_device(a->dev, a->table->sgl, a->table->nents,
				       direction);
	}
	mutex_unlock(&res->lock);

	return 0;
}

static const struct dma_buf_ops dma_buf_ops = {
	.map_dma_buf = vc_sm_map_dma_buf,
	.unmap_dma_buf = vc_sm_unmap_dma_buf,
	.mmap = vc_sm_dmabuf_mmap,
	.release = vc_sm_dma_buf_release,
	.attach = vc_sm_dma_buf_attach,
	.detach = vc_sm_dma_buf_detatch,
	.begin_cpu_access = vc_sm_dma_buf_begin_cpu_access,
	.end_cpu_access = vc_sm_dma_buf_end_cpu_access,
	.map_atomic = vc_sm_dma_buf_kmap,
	.unmap_atomic = vc_sm_dma_buf_kunmap,
	.map = vc_sm_dma_buf_kmap,
	.unmap = vc_sm_dma_buf_kunmap,
};

/* A set of dma_buf functions that call through to the exporter */
static
int vc_sm_import_dma_buf_attach(struct dma_buf *dmabuf, struct device *dev,
				struct dma_buf_attachment *attachment)
{
	struct vc_sm_buffer *res = dmabuf->priv;

	if (!res->import_dma_buf)
		return -EINVAL;
	return res->import_dma_buf->ops->attach(res->import_dma_buf, dev,
						attachment);
}

static
void vc_sm_import_dma_buf_detatch(struct dma_buf *dmabuf,
				  struct dma_buf_attachment *attachment)
{
	struct vc_sm_buffer *res = dmabuf->priv;

	if (!res->import_dma_buf)
		return;
	res->import_dma_buf->ops->detach(res->import_dma_buf, attachment);
}

static
struct sg_table *vc_sm_import_map_dma_buf(struct dma_buf_attachment *attachment,
					  enum dma_data_direction direction)
{
	struct vc_sm_buffer *res = attachment->dmabuf->priv;

	if (!res->import_dma_buf)
		return NULL;
	return res->import_dma_buf->ops->map_dma_buf(attachment, direction);
}

static
void vc_sm_import_unmap_dma_buf(struct dma_buf_attachment *attachment,
				struct sg_table *table,
				enum dma_data_direction direction)
{
	struct vc_sm_buffer *res = attachment->dmabuf->priv;

	if (!res->import_dma_buf)
		return;
	res->import_dma_buf->ops->unmap_dma_buf(attachment, table, direction);
}

static
int vc_sm_import_dmabuf_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct vc_sm_buffer *res = dmabuf->priv;

	pr_debug("%s: mmap dma_buf %p, res %p, imported db %p\n", __func__,
		 dmabuf, res, res->import_dma_buf);
	if (!res->import_dma_buf) {
		pr_err("%s: mmap dma_buf %p- not an imported buffer\n",
		       __func__, dmabuf);
		return -EINVAL;
	}
	return res->import_dma_buf->ops->mmap(res->import_dma_buf, vma);
}

static
void vc_sm_import_dma_buf_release(struct dma_buf *dmabuf)
{
	struct vc_sm_buffer *res = dmabuf->priv;

	pr_debug("%s: Relasing dma_buf %p\n", __func__, dmabuf);
	if (!res->import_dma_buf)
		return;

	/* Need to release imported handle */
	vc_sm_clean_up_dmabuf(res);

	vc_sm_release_resource(res, 0);
}

static
void *vc_sm_import_dma_buf_kmap(struct dma_buf *dmabuf,
				unsigned long offset)
{
	struct vc_sm_buffer *res = dmabuf->priv;

	if (!res->import_dma_buf)
		return NULL;
	return res->import_dma_buf->ops->map_atomic(res->import_dma_buf,
						      offset);
}

static
void vc_sm_import_dma_buf_kunmap(struct dma_buf *dmabuf,
				 unsigned long offset, void *ptr)
{
	struct vc_sm_buffer *res = dmabuf->priv;

	if (!res->import_dma_buf)
		return;
	res->import_dma_buf->ops->unmap_atomic(res->import_dma_buf,
					       offset, ptr);
}

static
int vc_sm_import_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
					  enum dma_data_direction direction)
{
	struct vc_sm_buffer *res = dmabuf->priv;

	if (!res->import_dma_buf)
		return -EINVAL;
	return res->import_dma_buf->ops->begin_cpu_access(res->import_dma_buf,
							    direction);
}

static
int vc_sm_import_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
					enum dma_data_direction direction)
{
	struct vc_sm_buffer *res = dmabuf->priv;

	if (!res->import_dma_buf)
		return -EINVAL;
	return res->import_dma_buf->ops->end_cpu_access(res->import_dma_buf,
							  direction);
}

static const struct dma_buf_ops dma_buf_import_ops = {
	.map_dma_buf = vc_sm_import_map_dma_buf,
	.unmap_dma_buf = vc_sm_import_unmap_dma_buf,
	.mmap = vc_sm_import_dmabuf_mmap,
	.release = vc_sm_import_dma_buf_release,
	.attach = vc_sm_import_dma_buf_attach,
	.detach = vc_sm_import_dma_buf_detatch,
	.begin_cpu_access = vc_sm_import_dma_buf_begin_cpu_access,
	.end_cpu_access = vc_sm_import_dma_buf_end_cpu_access,
	.map_atomic = vc_sm_import_dma_buf_kmap,
	.unmap_atomic = vc_sm_import_dma_buf_kunmap,
	.map = vc_sm_import_dma_buf_kmap,
	.unmap = vc_sm_import_dma_buf_kunmap,
};

static int vc_sm_cma_get_buffer(int fd, struct dma_buf **ret_dma_buf,
				struct vc_sm_buffer **ret_buffer)
{
	struct dma_buf *dma_buf = NULL;
	struct vc_sm_buffer *buffer = NULL;

	dma_buf = dma_buf_get(fd);
	if (IS_ERR_OR_NULL(dma_buf)) {
		pr_err("[%s]: fd %d failed\n", __func__, fd);
		return PTR_ERR(dma_buf);
	}

	if (dma_buf->ops == &dma_buf_ops ||
	    dma_buf->ops == &dma_buf_import_ops) {
		/* Our buffer - use priv field as reference */
		*ret_dma_buf = dma_buf;
		*ret_buffer = (struct vc_sm_buffer *)dma_buf->priv;

		return 0;
	} else {
		/*
		 * Not our buffer (this shouldn't happen as it should be mapped
		 * via dma_buf_import_ops).
		 * Can't use the priv field shortcut
		 * to our handle. (ie it is an imported dma_buf from elsewhere)
		 * Search the list of allocations to find dma_buf.
		 */
		int ret = -EINVAL;

		pr_debug("[%s]: NOT our buffer %p.\n", __func__, dma_buf->priv);

		if (!list_empty(&sm_state->buffer_list)) {
			list_for_each_entry(buffer, &sm_state->buffer_list,
					    global_buffer_list) {
				if (buffer->dma_buf == dma_buf) {
					*ret_dma_buf = dma_buf;
					*ret_buffer = buffer;
					ret = 0;
					break;
				}
			}
		}

		if (ret)
			dma_buf_put(dma_buf);

		return ret;
	}
}

static int vc_sm_cma_vpu_alloc(u32 size, uint32_t align, const char *name,
			       struct vc_sm_buffer **ret_buffer)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct vc_sm_buffer *buffer = NULL;
	int aligned_size;
	int ret = 0;

	/* Align to the user requested align */
	aligned_size = ALIGN(size, align);
	/* and then to a page boundary */
	aligned_size = PAGE_ALIGN(aligned_size);

	if (!aligned_size)
		return -EINVAL;

	/* Allocate local buffer to track this allocation. */
	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	if (vc_sm_cma_buffer_allocate(sm_state->cma_heap, buffer,
				      aligned_size)) {
		pr_err("[%s]: cma alloc of %d bytes failed\n",
		       __func__, aligned_size);
		ret = -ENOMEM;
		goto error;
	}

	pr_debug("[%s]: cma alloc of %d bytes success\n",
		 __func__, aligned_size);

	if (dma_map_sg(&sm_state->pdev->dev, buffer->sg_table->sgl,
		       buffer->sg_table->nents, DMA_BIDIRECTIONAL) <= 0) {
		pr_err("[%s]: dma_map_sg failed\n", __func__);
		goto error;
	}

	mutex_init(&buffer->lock);
	INIT_LIST_HEAD(&buffer->attachments);

	memcpy(buffer->name, name,
	       min(sizeof(buffer->name), strlen(name)));

	exp_info.ops = &dma_buf_ops;
	exp_info.size = aligned_size;
	exp_info.flags = O_RDWR;
	exp_info.priv = buffer;

	buffer->dma_buf = dma_buf_export(&exp_info);
	if (IS_ERR(buffer->dma_buf)) {
		ret = PTR_ERR(buffer->dma_buf);
		goto error;
	}
	buffer->dma_addr = (uint32_t)sg_dma_address(buffer->sg_table->sgl);
	buffer->private = sm_state->vpu_allocs;

	/* FIXME: I want to know this, but it's not been allocated as yet. */
	buffer->vc_handle = 0;
	buffer->vpu_state = VPU_MAPPED;
	buffer->vpu_allocated = 1;
	buffer->size = size;

	vc_sm_add_resource(sm_state->vpu_allocs, buffer);

	*ret_buffer = buffer;
	return 0;
error:
	if (buffer)
		vc_sm_destroy_buffer(buffer);
	return ret;
}

/*
 * Allocate a shared memory handle and block.
 * Allocation is from CMA, and then imported into the VPU mappings.
 */
int vc_sm_cma_ioctl_alloc(struct vc_sm_privdata_t *private,
			  struct vc_sm_cma_ioctl_alloc *ioparam)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct vc_sm_buffer *buffer = NULL;
	struct vc_sm_import import = { 0 };
	struct vc_sm_import_result result = { 0 };
	struct dma_buf *dmabuf = NULL;
	int aligned_size;
	int ret = 0;
	int status;
	int fd = -1;

	aligned_size = PAGE_ALIGN(ioparam->size);

	if (!aligned_size)
		return -EINVAL;

	/* Allocate local buffer to track this allocation. */
	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto error;
	}

	if (vc_sm_cma_buffer_allocate(sm_state->cma_heap, buffer,
				      aligned_size)) {
		pr_err("[%s]: cma alloc of %d bytes failed\n",
		       __func__, aligned_size);
		kfree(buffer);
		return -ENOMEM;
	}

	if (dma_map_sg(&sm_state->pdev->dev, buffer->sg_table->sgl,
		       buffer->sg_table->nents, DMA_BIDIRECTIONAL) <= 0) {
		pr_err("[%s]: dma_map_sg failed\n", __func__);
		goto error;
	}

	import.type = //((ioparam->cached == VMCS_SM_CACHE_VC) ||
		      // (ioparam->cached == VMCS_SM_CACHE_BOTH)) ?
			//	VC_SM_ALLOC_CACHED :
				VC_SM_ALLOC_NON_CACHED;
	import.allocator = current->tgid;

	if (*ioparam->name)
		memcpy(import.name, ioparam->name, sizeof(import.name) - 1);
	else
		memcpy(import.name, VC_SM_RESOURCE_NAME_DEFAULT,
		       sizeof(VC_SM_RESOURCE_NAME_DEFAULT));

	mutex_init(&buffer->lock);
	INIT_LIST_HEAD(&buffer->attachments);
	buffer->ref_count++;
	buffer->pid = current->tgid;
	memcpy(buffer->name, import.name,
	       min(sizeof(buffer->name), sizeof(import.name) - 1));

	exp_info.ops = &dma_buf_ops;
	exp_info.size = aligned_size;
	exp_info.flags = O_RDWR;
	exp_info.priv = buffer;

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto error;
	}
	buffer->dma_buf = dmabuf;

	import.addr = (uint32_t)sg_dma_address(buffer->sg_table->sgl);
	import.size = aligned_size;
	import.kernel_id = (uint32_t)buffer;

	pr_debug("[%s]: alloced and exported \"%s\" data - type %u, addr %p, size %u, now to import to VC\n",
		 __func__, import.name, import.type, (void *)import.addr,
		 import.size);

	/* Wrap it into a videocore buffer. */
	status = vc_sm_vchi_import(sm_state->sm_handle, &import, &result,
				   &sm_state->int_trans_id);
	if (status == -EINTR) {
		pr_debug("[%s]: requesting import memory action restart (trans_id: %u)\n",
			 __func__, sm_state->int_trans_id);
		ret = -ERESTARTSYS;
		private->restart_sys = -EINTR;
		private->int_action = VC_SM_MSG_TYPE_IMPORT;
		goto error;
	} else if (status || !result.res_handle) {
		pr_err("[%s]: failed to import memory on videocore (status: %u, trans_id: %u)\n",
		       __func__, status, sm_state->int_trans_id);
		ret = -ENOMEM;
		goto error;
	}

	/* Keep track of the buffer we created. */
	buffer->private = private;
	buffer->vc_handle = result.res_handle;
	buffer->size = import.size;
	buffer->dma_addr = import.addr;
	buffer->vpu_state = VPU_MAPPED;

	pr_debug("[%s]: imported to VC as handle %08X\n",
		 __func__, buffer->vc_handle);

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0)
		dma_buf_put(dmabuf);

	vc_sm_add_resource(private, buffer);

	pr_debug("[%s]: Added resource as fd %d, buffer %p, private %p, dma_addr %08X\n",
		 __func__, fd, buffer, private, buffer->dma_addr);
	/* We're done */
	ioparam->handle = fd;
	return 0;

error:
	if (buffer) {
		pr_err("[%s]: something failed - cleanup\n", __func__);

		vc_sm_destroy_buffer(buffer);
	}
	return ret;
}

/* Import a dma_buf to be shared with VC. */
int
vc_sm_cma_import_dmabuf_internal(struct vc_sm_privdata_t *private,
				 struct vc_sm_cma_ioctl_import_dmabuf *ioparam,
				 struct dma_buf *src_dma_buf,
				 struct dma_buf **imported_buf)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct vc_sm_buffer *buffer = NULL;
	struct vc_sm_import import = { };
	struct vc_sm_import_result result = { };
	struct dma_buf *dma_buf;
	struct dma_buf_attachment *attach = NULL;
	struct sg_table *sgt = NULL;
	int ret = 0;
	int status;

	/* Setup our allocation parameters */
	pr_debug("%s: Import fd %d / src_dma_buf %p\n", __func__,
		 ioparam->dmabuf_fd, src_dma_buf);
	if (src_dma_buf) {
		get_dma_buf(src_dma_buf);
		dma_buf = src_dma_buf;
	} else {
		dma_buf = dma_buf_get(ioparam->dmabuf_fd);
	}

	if (IS_ERR(dma_buf))
		return PTR_ERR(dma_buf);

	if (dma_buf->ops == &dma_buf_ops) {
		/* Importing our own export - my head hurts. */
		pr_err("%s: dma_buf ops are ours :-( %p\n", __func__, dma_buf->ops);
		ret =  -EINVAL;
		goto error;
	}

	attach = dma_buf_attach(dma_buf, &sm_state->pdev->dev);
	if (IS_ERR(attach)) {
		ret = PTR_ERR(attach);
		goto error;
	}

	sgt = dma_buf_map_attachment(attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(sgt)) {
		ret = PTR_ERR(sgt);
		goto error;
	}

	/* Verify that the address block is contiguous */
	if (sgt->nents != 1) {
		ret = -ENOMEM;
		goto error;
	}

	/* Allocate local buffer to track this allocation. */
	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto error;
	}

	import.type = //((ioparam->cached == VMCS_SM_CACHE_VC) ||
		      // (ioparam->cached == VMCS_SM_CACHE_BOTH)) ?
			//	VC_SM_ALLOC_CACHED :
				VC_SM_ALLOC_NON_CACHED;
	import.addr = (uint32_t)sg_dma_address(sgt->sgl);
	import.size = sg_dma_len(sgt->sgl);
	import.allocator = current->tgid;
	import.kernel_id = (uint32_t)buffer;	//FIXME: 64 bit support needed.

	if (*ioparam->name)
		memcpy(import.name, ioparam->name, sizeof(import.name) - 1);
	else
		memcpy(import.name, VC_SM_RESOURCE_NAME_DEFAULT,
		       sizeof(VC_SM_RESOURCE_NAME_DEFAULT));

	pr_debug("[%s]: attempt to import \"%s\" data - type %u, addr %p, size %u\n",
		 __func__, import.name, import.type, (void *)import.addr,
		 import.size);

	/* Allocate the videocore buffer. */
	status = vc_sm_vchi_import(sm_state->sm_handle, &import, &result,
				   &sm_state->int_trans_id);
	if (status == -EINTR) {
		pr_debug("[%s]: requesting import memory action restart (trans_id: %u)\n",
			 __func__, sm_state->int_trans_id);
		ret = -ERESTARTSYS;
		private->restart_sys = -EINTR;
		private->int_action = VC_SM_MSG_TYPE_IMPORT;
		goto error;
	} else if (status || !result.res_handle) {
		pr_debug("[%s]: failed to import memory on videocore (status: %u, trans_id: %u)\n",
			 __func__, status, sm_state->int_trans_id);
		ret = -ENOMEM;
		goto error;
	}

	mutex_init(&buffer->lock);
	INIT_LIST_HEAD(&buffer->attachments);
	buffer->ref_count++;
	buffer->pid = current->tgid;
	memcpy(buffer->name, import.name,
	       min(sizeof(buffer->name), sizeof(import.name) - 1));

	/* Keep track of the buffer we created. */
	buffer->private = private;
	buffer->vc_handle = result.res_handle;
	buffer->size = import.size;
	buffer->vpu_state = VPU_MAPPED;

	buffer->import_dma_buf = dma_buf;

	buffer->attach = attach;
	buffer->sgt = sgt;
	buffer->dma_addr = sg_dma_address(sgt->sgl);

	/*
	 * We're done - we need to export a new dmabuf chaining through most
	 * functions, but enabling us to release our own internal references
	 * here.
	 */
	exp_info.ops = &dma_buf_import_ops;
	exp_info.size = import.size;
	exp_info.flags = O_RDWR;
	exp_info.priv = buffer;

	buffer->dma_buf = dma_buf_export(&exp_info);
	if (IS_ERR(buffer->dma_buf)) {
		ret = PTR_ERR(buffer->dma_buf);
		goto error;
	}

	vc_sm_add_resource(private, buffer);

	*imported_buf = buffer->dma_buf;

	return 0;

error:
	if (result.res_handle) {
		struct vc_sm_free_t free = { result.res_handle, 0 };

		vc_sm_vchi_free(sm_state->sm_handle, &free,
				&sm_state->int_trans_id);
	}
	kfree(buffer);
	if (sgt)
		dma_buf_unmap_attachment(attach, sgt, DMA_BIDIRECTIONAL);
	if (attach)
		dma_buf_detach(dma_buf, attach);
	dma_buf_put(dma_buf);
	return ret;
}

/* Imports a dma_buf represented by a file descriptor to be shared with VC */
int vc_sm_cma_ioctl_import_dmabuf(struct vc_sm_privdata_t *private,
				  struct vc_sm_cma_ioctl_import_dmabuf *ioparam,
			      struct dma_buf *src_dma_buf)
{
	struct dma_buf *imported_buf;
	int ret;

	ret = vc_sm_cma_import_dmabuf_internal(private, ioparam, src_dma_buf,
					       &imported_buf);
	if (!ret) {
		struct vc_sm_buffer *buf =
				(struct vc_sm_buffer *)imported_buf->priv;

		ioparam->handle = dma_buf_fd(imported_buf, O_CLOEXEC);
		ioparam->size = buf->size;
	}
	pr_debug("[%s]: Returning handle of %d\n", __func__, ioparam->handle);
	return ret;
}

/* Handle control from host. */
static long vc_sm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	unsigned int cmdnr = _IOC_NR(cmd);
	struct vc_sm_privdata_t *file_data =
	    (struct vc_sm_privdata_t *)file->private_data;

	/* Validate we can work with this device. */
	if (!sm_state || !file_data) {
		pr_err("[%s]: invalid device\n", __func__);
		return -EPERM;
	}

	pr_debug("[%s]: cmd %x tgid %u, owner %u\n", __func__, cmdnr,
		 current->tgid, file_data->pid);

	/* Action is a re-post of a previously interrupted action? */
	if (file_data->restart_sys == -EINTR) {
		struct vc_sm_action_clean_t action_clean;

		pr_debug("[%s]: clean up of action %u (trans_id: %u) following EINTR\n",
			 __func__, file_data->int_action,
			file_data->int_trans_id);

		action_clean.res_action = file_data->int_action;
		action_clean.action_trans_id = sm_state->int_trans_id;

		vc_sm_vchi_clean_up(sm_state->sm_handle, &action_clean);

		file_data->restart_sys = 0;
	}

	/* Now process the command. */
	switch (cmdnr) {
		/* New memory allocation.
		 */
	case VC_SM_CMA_CMD_ALLOC:
		{
			struct vc_sm_cma_ioctl_alloc ioparam;

			/* Get the parameter data. */
			if (copy_from_user
			    (&ioparam, (void *)arg, sizeof(ioparam)) != 0) {
				pr_err("[%s]: failed to copy-from-user for cmd %x\n",
				       __func__, cmdnr);
				ret = -EFAULT;
				goto out;
			}

			ret = vc_sm_cma_ioctl_alloc(file_data, &ioparam);
			if (!ret &&
			    (copy_to_user((void *)arg,
					  &ioparam, sizeof(ioparam)) != 0)) {
				pr_err("[%s]: failed to copy-to-user for cmd %x\n",
				       __func__, cmdnr);
				ret = -EFAULT;
				//FIXME: Free the allocation.
			}
		}
		break;

	case VC_SM_CMA_CMD_IMPORT_DMABUF:
		{
			struct vc_sm_cma_ioctl_import_dmabuf ioparam;

			/* Get the parameter data. */
			if (copy_from_user
			    (&ioparam, (void *)arg, sizeof(ioparam)) != 0) {
				pr_err("[%s]: failed to copy-from-user for cmd %x\n",
				       __func__, cmdnr);
				ret = -EFAULT;
				goto out;
			}

			ret = vc_sm_cma_ioctl_import_dmabuf(file_data, &ioparam,
							    NULL);
			if (!ret &&
			    (copy_to_user((void *)arg,
					  &ioparam, sizeof(ioparam)) != 0)) {
				pr_err("[%s]: failed to copy-to-user for cmd %x\n",
				       __func__, cmdnr);
				//FIXME: release the resource
				ret = -EFAULT;
			}
		}
		break;

#if TEMPORARILY_DISABLED
//FIXME: Do we care about these from userspace?
		/* Walk allocation on videocore, information shows up in the
		 ** videocore log.
		 */
	case VC_SM_CMA_CMD_VC_WALK_ALLOC:
		{
			pr_debug("[%s]: invoking walk alloc\n", __func__);

			if (vc_sm_vchi_walk_alloc(sm_state->sm_handle) != 0)
				pr_err("[%s]: failed to walk-alloc on videocore\n",
				       __func__);
		}
		break;
		/* Walk mapping table on host, information shows up in the
		 ** kernel log.
		 */
	case VC_SM_CMA_CMD_HOST_WALK_MAP:
		{
			/* Use pid of -1 to tell to walk the whole map. */
			vmcs_sm_host_walk_map_per_pid(-1);
		}
		break;
#endif
#if TEMPORARILY_DISABLED
//FIXME: Do we care about these from userspace?
		/* Walk mapping table per process on host.  */
	case VC_SM_CMA_CMD_HOST_WALK_PID_ALLOC:
		{
			struct vc_sm_cma_ioctl_walk ioparam;

			/* Get parameter data.  */
			if (copy_from_user(&ioparam,
					   (void *)arg, sizeof(ioparam)) != 0) {
				pr_err("[%s]: failed to copy-from-user for cmd %x\n",
				       __func__, cmdnr);
				ret = -EFAULT;
				goto out;
			}

			vmcs_sm_host_walk_alloc(file_data);
		}
		break;

		/* Walk allocation per process on host.  */
	case VC_SM_CMA_CMD_HOST_WALK_PID_MAP:
		{
			struct vc_sm_cma_ioctl_walk ioparam;

			/* Get parameter data. */
			if (copy_from_user(&ioparam,
					   (void *)arg, sizeof(ioparam)) != 0) {
				pr_err("[%s]: failed to copy-from-user for cmd %x\n",
				       __func__, cmdnr);
				ret = -EFAULT;
				goto out;
			}

			vmcs_sm_host_walk_map_per_pid(ioparam.pid);
		}
		break;
#endif

	case VC_SM_CMA_CMD_MAPPED_VC_HDL_FROM_HDL:
	case VC_SM_CMA_CMD_MAPPED_VC_ADDR_FROM_HDL:
		{
			struct vc_sm_cma_ioctl_map ioparam;
			struct dma_buf *dma_buf;
			struct vc_sm_buffer *buf;

			/* Get the parameter data. */
			if (copy_from_user
			    (&ioparam, (void *)arg, sizeof(ioparam)) != 0) {
				pr_err("[%s]: failed to copy-from-user for cmd %x\n",
				       __func__, cmdnr);
				return -EFAULT;
			}
			pr_debug("[%s]: VC_FROM_xxx cmd %x - fd is %d\n",
				 __func__, cmdnr, ioparam.fd);

			ret = vc_sm_cma_get_buffer(ioparam.fd, &dma_buf, &buf);
			if (ret)
				return ret;

			ioparam.handle = buf->vc_handle;
			if (buf->sg_table) {
				ioparam.addr = (uint32_t)sg_phys(buf->sg_table->sgl);
			} else {
				ioparam.addr = buf->dma_addr;
				pr_debug("[%s]: VC_FROM_xxx %x, fd %d - no sg_table. Not our buffer/imported? Using dma_addr %08X, sgt %p",
					 __func__, cmdnr, ioparam.fd, buf->dma_addr, buf->sgt);
			}
			ioparam.size = buf->size;
			dma_buf_put(dma_buf);
			pr_debug("[%s]: VC_FROM_xxx %x, fd %d success\n", __func__, cmdnr, ioparam.fd);

			if ((copy_to_user((void *)arg,
					  &ioparam, sizeof(ioparam)) != 0)) {
				pr_err("[%s]: failed to copy-to-user for cmd %x\n",
				       __func__, cmdnr);
				ret = -EFAULT;
				//FIXME: Free the allocation.
			}
		}
		break;

		/* Flush the cache for a given mapping. */
	case VC_SM_CMA_CMD_FLUSH:
		{
#if TEMPORARILY_DISABLED
			//FIXME: Temporarily disable. Do we really need mm_vc_mem_phys_addr?
			//should be able to flush via CMA calls
			struct vc_sm_cma_ioctl_cache ioparam;

			/* Get parameter data. */
			if (copy_from_user(&ioparam,
					   (void *)arg, sizeof(ioparam)) != 0) {
				pr_err("[%s]: failed to copy-from-user for cmd %x\n",
				       __func__, cmdnr);
				ret = -EFAULT;
				goto out;
			}

			/* Locate buffer from GUID. */
			buffer =
			    vc_sm_acquire_buffer(file_data, ioparam.handle);

			if (buffer && buffer->res_cached) {
				dma_addr_t phys_addr = 0;

				phys_addr =
				    (dma_addr_t)((uint32_t)
						 buffer->res_base_mem &
						 0x3FFFFFFF);
				phys_addr += (dma_addr_t)mm_vc_mem_phys_addr;

				/* L1 cache flush */
				down_read(&current->mm->mmap_sem);
				vcsm_vma_cache_clean_page_range((unsigned long)
								ioparam.addr,
								(unsigned long)
								ioparam.addr +
								ioparam.size);
				up_read(&current->mm->mmap_sem);

				/* L2 cache flush */
				outer_clean_range(phys_addr,
						  phys_addr +
						  (size_t)ioparam.size);
			} else if (!buffer) {
				ret = -EINVAL;
				goto out;
			}

			if (buffer)
				vc_sm_release_resource(buffer, 0);
#endif
		}
		break;

		/* Invalidate the cache for a given mapping. */
	case VC_SM_CMA_CMD_INVALID:
		{
#if TEMPORARILY_DISABLED
			struct vc_sm_cma_ioctl_cache ioparam;

			/* Get parameter data. */
			if (copy_from_user(&ioparam,
					   (void *)arg, sizeof(ioparam)) != 0) {
				pr_err("[%s]: failed to copy-from-user for cmd %x\n",
				       __func__, cmdnr);
				ret = -EFAULT;
				goto out;
			}

			/* Locate buffer from GUID. */
			buffer =
			    vc_sm_acquire_buffer(file_data, ioparam.handle);

			if (buffer && buffer->res_cached) {
				dma_addr_t phys_addr = 0;

				phys_addr =
				    (dma_addr_t)((uint32_t)
						 buffer->res_base_mem &
						 0x3FFFFFFF);
				phys_addr += (dma_addr_t)mm_vc_mem_phys_addr;

				/* L2 cache invalidate */
				outer_inv_range(phys_addr,
						phys_addr +
						(size_t)ioparam.size);

				/* L1 cache invalidate */
				down_read(&current->mm->mmap_sem);
				vcsm_vma_cache_clean_page_range((unsigned long)
								ioparam.addr,
								(unsigned long)
								ioparam.addr +
								ioparam.size);
				up_read(&current->mm->mmap_sem);
			} else if (!buffer) {
				ret = -EINVAL;
				goto out;
			}

			if (buffer)
				vc_sm_release_resource(buffer, 0);
#endif
		}
		break;

	/* Flush/Invalidate the cache for a given mapping. */
	case VC_SM_CMA_CMD_CLEAN_INVALID:
		{
#if TEMPORARILY_DISABLED
			int i;
			struct vc_sm_cma_ioctl_clean_invalid ioparam;

			/* Get parameter data. */
			if (copy_from_user(&ioparam,
					   (void *)arg, sizeof(ioparam)) != 0) {
				pr_err("[%s]: failed to copy-from-user for cmd %x\n",
				       __func__, cmdnr);
				ret = -EFAULT;
				goto out;
			}
			for (i = 0; i < sizeof(ioparam.s) / sizeof(*ioparam.s); i++) {
				switch (ioparam.s[i].cmd) {
				default:
				case 0:
					break; /* NOOP */
				case 1:	/* L1/L2 invalidate virtual range */
				case 2: /* L1/L2 clean physical range */
				case 3: /* L1/L2 clean+invalidate all */
					/* Locate buffer from GUID. */
					buffer =
					    vc_sm_acquire_buffer(file_data, ioparam.s[i].handle);

					if ((buffer) && buffer->res_cached) {
						unsigned long base = ioparam.s[i].addr & ~(PAGE_SIZE - 1);
						unsigned long end = (ioparam.s[i].addr + ioparam.s[i].size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

						/* L1/L2 cache flush */
						down_read(&current->mm->mmap_sem);
						vcsm_vma_cache_clean_page_range(base, end);
						up_read(&current->mm->mmap_sem);
					} else if (!buffer) {
						ret = -EINVAL;
						goto out;
					}

					if (buffer)
						vc_sm_release_resource(buffer, 0);

					break;
				}
			}
#endif
		}
		break;
	/* Flush/Invalidate the cache for a given mapping. */
	case VC_SM_CMA_CMD_CLEAN_INVALID2:
		{
#if TEMPORARILY_DISABLED
				int i, j;
				struct vc_sm_cma_ioctl_clean_invalid2 ioparam;
				struct vc_sm_cma_ioctl_clean_invalid_block *block = NULL;

				/* Get parameter data. */
				if (copy_from_user(&ioparam,
						   (void *)arg, sizeof(ioparam)) != 0) {
					pr_err("[%s]: failed to copy-from-user header for cmd %x\n",
					       __func__, cmdnr);
					ret = -EFAULT;
					goto out;
				}
				block = kmalloc(ioparam.op_count *
						sizeof(struct vmcs_sm_ioctl_clean_invalid_block),
						GFP_KERNEL);
				if (!block) {
					ret = -EFAULT;
					goto out;
				}
				if (copy_from_user(block,
						   (void *)(arg + sizeof(ioparam)), ioparam.op_count * sizeof(struct vc_sm_cma_ioctl_clean_invalid_block)) != 0) {
					pr_err("[%s]: failed to copy-from-user payload for cmd %x\n",
					       __func__, cmdnr);
					ret = -EFAULT;
					goto out;
				}

				for (i = 0; i < ioparam.op_count; i++) {
					const struct vc_sm_cma_ioctl_clean_invalid_block * const op = block + i;
					cache_flush_op_fn * const op_fn = flushops[op->invalidate_mode & 3];

					if ((op->invalidate_mode & ~3) != 0) {
						ret = -EINVAL;
						break;
					}

					if (op_fn == 0)
						continue;

					for (j = 0; j < op->block_count; ++j) {
						const char * const base = (const char *)op->start_address + j * op->inter_block_stride;
						const char * const end = base + op->block_size;

						op_fn(base, end);
					}
				}
				kfree(block);
#endif
			}
		break;

	default:
		ret = -EINVAL;
		break;
	}

out:
	return ret;
}

/* FIXME: Pass a function pointer to this into vc_vchi_sm.c */
void
vc_sm_vpu_event(struct sm_instance *instance, struct vc_sm_result_t *reply,
		int reply_len)
{
	switch (reply->trans_id & ~0x80000000) {
	case VC_SM_MSG_TYPE_CLIENT_VERSION:
	{
		/* Acknowledge that the firmware supports the version command */
		pr_debug("%s: firmware acked version msg. Require release cb\n",
			 __func__);
		sm_state->require_released_callback = true;
	}
	break;
	case VC_SM_MSG_TYPE_RELEASED:
	{
		struct vc_sm_released *release = (struct vc_sm_released *)reply;
		struct vc_sm_buffer *buffer =
				(struct vc_sm_buffer *)release->kernel_id;

		/*
		 * FIXME: Need to check buffer is still valid and allocated
		 * before continuing
		 */
		pr_debug("%s: Released addr %08x, size %u, id %08X, mem_handle %08X\n",
			 __func__, release->addr, release->size,
			 release->kernel_id, release->vc_handle);
		buffer->vc_handle = 0;
		buffer->vpu_state = VPU_NOT_MAPPED;
		if (buffer->vpu_allocated)
			dma_buf_put(buffer->dma_buf);

		vc_sm_release_resource(buffer, 0);
	}
	break;
	case VC_SM_MSG_TYPE_VC_MEM_REQUEST:
	{
		struct vc_sm_buffer *buffer = NULL;
		struct vc_sm_vc_mem_request *req =
					(struct vc_sm_vc_mem_request *)reply;
		struct vc_sm_vc_mem_request_result reply;
		int ret;

		pr_debug("%s: Request %u bytes of memory, align %d name %s, trans_id %08x\n",
			 __func__, req->size, req->align, req->name,
			 req->trans_id);
		ret = vc_sm_cma_vpu_alloc(req->size, req->align, req->name,
					  &buffer);

		reply.trans_id = req->trans_id;
		if (!ret) {
			reply.addr = buffer->dma_addr;
			reply.kernel_id = (uint32_t)buffer;
			pr_debug("%s: Allocated resource buffer %p, addr %pad\n",
				 __func__, buffer, &buffer->dma_addr);
		} else {
			pr_err("%s: Allocation failed\n", __func__);
			reply.addr = 0;
			reply.kernel_id = 0;
		}
		vc_sm_vchi_client_vc_mem_req_reply(sm_state->sm_handle, &reply,
						   &sm_state->int_trans_id);
		break;
	}
	break;
	default:
		pr_err("%s: Unknown vpu cmd %X\n", __func__, reply->trans_id);
		break;
	}
}

/* Device operations that we managed in this driver. */
static const struct file_operations vc_sm_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = vc_sm_ioctl,
	.open = vc_sm_cma_open,
	.release = vc_sm_cma_release,
};

/* Videocore connected.  */
static void vc_sm_connected_init(void)
{
	int ret;
	VCHI_INSTANCE_T vchi_instance;
	VCHI_CONNECTION_T *vchi_connection = NULL;
	struct vc_sm_version version;
	struct vc_sm_result_t version_result;

	pr_info("[%s]: start\n", __func__);

	if (vc_sm_cma_add_heaps(&sm_state->cma_heap) ||
	    !sm_state->cma_heap) {
		pr_err("[%s]: failed to initialise CMA heaps\n",
		       __func__);
		ret = -EIO;
		goto err_free_mem;
	}

	/*
	 * Initialize and create a VCHI connection for the shared memory service
	 * running on videocore.
	 */
	ret = vchi_initialise(&vchi_instance);
	if (ret) {
		pr_err("[%s]: failed to initialise VCHI instance (ret=%d)\n",
		       __func__, ret);

		ret = -EIO;
		goto err_free_mem;
	}

	ret = vchi_connect(NULL, 0, vchi_instance);
	if (ret) {
		pr_err("[%s]: failed to connect VCHI instance (ret=%d)\n",
		       __func__, ret);

		ret = -EIO;
		goto err_free_mem;
	}

	/* Initialize an instance of the shared memory service. */
	sm_state->sm_handle =
	    vc_sm_vchi_init(vchi_instance, &vchi_connection, 1);
	if (!sm_state->sm_handle) {
		pr_err("[%s]: failed to initialize shared memory service\n",
		       __func__);

		ret = -EPERM;
		goto err_free_mem;
	}

	/* Create a debug fs directory entry (root). */
	sm_state->dir_root = debugfs_create_dir(VC_SM_DIR_ROOT_NAME, NULL);
	if (!sm_state->dir_root) {
		pr_err("[%s]: failed to create \'%s\' directory entry\n",
		       __func__, VC_SM_DIR_ROOT_NAME);

		ret = -EPERM;
		goto err_stop_sm_service;
	}

	sm_state->dir_state.show = &vc_sm_cma_global_state_show;
	sm_state->dir_state.dir_entry =
		debugfs_create_file(VC_SM_STATE, 0444, sm_state->dir_root,
				    &sm_state->dir_state,
				    &vc_sm_cma_debug_fs_fops);
#if TEMPORARILY_DISABLED
	sm_state->dir_stats.show = &vc_sm_global_statistics_show;
	sm_state->dir_stats.dir_entry =
		debugfs_create_file(VC_SM_STATS, 0444, sm_state->dir_root,
				    &sm_state->dir_stats, &vc_sm_debug_fs_fops);

	/* Create the proc entry children. */
	sm_state->dir_alloc =
		debugfs_create_dir(VC_SM_DIR_ALLOC_NAME, sm_state->dir_root);
#endif
	/* Create a shared memory device. */
	sm_state->dev.minor = MISC_DYNAMIC_MINOR;
	sm_state->dev.name = DEVICE_NAME;
	sm_state->dev.fops = &vc_sm_ops;
	sm_state->dev.parent = NULL;
	ret = misc_register(&sm_state->dev);
	if (ret) {
		pr_err("vcsm-cma: failed to register misc device.\n");
		goto err_remove_debugfs;
	}

	INIT_LIST_HEAD(&sm_state->buffer_list);

	sm_state->data_knl = vc_sm_cma_create_priv_data(0);
	if (!sm_state->data_knl) {
		pr_err("[%s]: failed to create kernel private data tracker\n",
		       __func__);
		goto err_remove_shared_memory;
	}
	sm_state->vpu_allocs = vc_sm_cma_create_priv_data(0);
	if (!sm_state->vpu_allocs) {
		pr_err("[%s]: failed to create vpu_alloc private data tracker\n",
		       __func__);
		goto err_remove_shared_memory;
	}

	ret = vc_sm_vchi_client_version(sm_state->sm_handle, &version,
					&version_result,
					&sm_state->int_trans_id);
	if (ret) {
		pr_err("[%s]: Failed to send version request %d\n", __func__,
		       ret);
	}

	/* Done! */
	sm_inited = 1;
	pr_info("[%s]: installed successfully\n", __func__);
	return;

err_remove_shared_memory:
	misc_deregister(&sm_state->dev);
err_remove_debugfs:
	debugfs_remove_recursive(sm_state->dir_root);
err_stop_sm_service:
	vc_sm_vchi_stop(&sm_state->sm_handle);
err_free_mem:
	kfree(sm_state);
	pr_info("[%s]: failed, ret %d\n", __func__, ret);
}

/* Driver loading. */
static int bcm2835_vc_sm_cma_probe(struct platform_device *pdev)
{
	pr_info("vc-sm: Videocore shared memory driver\n");

	sm_state = kzalloc(sizeof(*sm_state), GFP_KERNEL);
	if (!sm_state)
		return -ENOMEM;
	sm_state->pdev = pdev;
	mutex_init(&sm_state->map_lock);

	vchiq_add_connected_callback(vc_sm_connected_init);
	return 0;
}

/* Driver unloading. */
static int bcm2835_vc_sm_cma_remove(struct platform_device *pdev)
{
	pr_debug("[%s]: start\n", __func__);
	if (sm_inited) {
		/* Remove shared memory device. */
		misc_deregister(&sm_state->dev);

		/* Remove all proc entries. */
		//debugfs_remove_recursive(sm_state->dir_root);

		/* Stop the videocore shared memory service. */
		vc_sm_vchi_stop(&sm_state->sm_handle);

		/* Free the memory for the state structure. */
		mutex_destroy(&sm_state->map_lock);
		kfree(sm_state);
	}

	pr_debug("[%s]: end\n", __func__);
	return 0;
}

#if defined(__KERNEL__)
/* Allocate a shared memory handle and block. */
int vc_sm_cma_alloc(struct vc_sm_cma_knl_alloc_t *alloc, int *handle)
{
	/* FIXME - needs implementing */
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(vc_sm_cma_alloc);

/* Get an internal resource handle mapped from the external one. */
int vc_sm_cma_int_handle(int handle)
{
	struct dma_buf *dma_buf = (struct dma_buf *)handle;
	struct vc_sm_buffer *res;

	/* Validate we can work with this device. */
	if (!sm_state || !handle) {
		pr_err("[%s]: invalid input\n", __func__);
		return 0;
	}

	res = (struct vc_sm_buffer *)dma_buf->priv;
	return res->vc_handle;
}
EXPORT_SYMBOL_GPL(vc_sm_cma_int_handle);

/* Free a previously allocated shared memory handle and block. */
int vc_sm_cma_free(int handle)
{
	struct dma_buf *dma_buf = (struct dma_buf *)handle;

	/* Validate we can work with this device. */
	if (!sm_state || !handle) {
		pr_err("[%s]: invalid input\n", __func__);
		return -EPERM;
	}

	pr_err("%s: handle %d/dmabuf %p\n", __func__, handle, dma_buf);

	dma_buf_put(dma_buf);

	return 0;
}
EXPORT_SYMBOL_GPL(vc_sm_cma_free);

/* Lock a memory handle for use by kernel. */
int vc_sm_cma_lock(int handle, enum vc_sm_lock_cache_mode mode,
		   unsigned long *data)
{
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(vc_sm_cma_lock);

/* Unlock a memory handle in use by kernel. */
int vc_sm_cma_unlock(int handle, int flush, int no_vc_unlock)
{
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(vc_sm_cma_unlock);

/* Map a shared memory region for use by kernel. */
int vc_sm_cma_map(int handle, unsigned int sm_addr,
		  enum vc_sm_lock_cache_mode mode, unsigned long *data)
{
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(vc_sm_cma_map);

/* Import a dmabuf to be shared with VC. */
int vc_sm_cma_import_dmabuf(struct dma_buf *src_dmabuf, int *handle)
{
	struct vc_sm_cma_ioctl_import_dmabuf ioparam = { 0 };
	struct dma_buf *new_dma_buf;
	struct vc_sm_buffer *res;
	int ret;

	/* Validate we can work with this device. */
	if (!sm_state || !src_dmabuf || !handle) {
		pr_err("[%s]: invalid input\n", __func__);
		return -EPERM;
	}

	ioparam.cached = 0;
	strcpy(ioparam.name, "KRNL DMABUF");

	ret = vc_sm_cma_import_dmabuf_internal(sm_state->data_knl, &ioparam,
					       src_dmabuf, &new_dma_buf);

	if (!ret) {
		pr_err("%s: imported to ptr %p\n", __func__, new_dma_buf);
		res = (struct vc_sm_buffer *)new_dma_buf->priv;
		res->pid = 0;

		/* Assign valid handle at this time.*/
		*handle = (int)new_dma_buf;
	} else {
		/*
		 * succeeded in importing the dma_buf, but then
		 * failed to look it up again. How?
		 * Release the fd again.
		 */
		pr_err("%s: imported vc_sm_cma_get_buffer failed %d\n",
		       __func__, ret);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(vc_sm_cma_import_dmabuf);

/* Export a dmabuf */
int vc_sm_cma_export_dmabuf(int handle, struct dma_buf **dmabuf)
{
	struct dma_buf *dma_buf = (struct dma_buf *)handle;

	/* Validate we can work with this device. */
	if (!sm_state || !handle) {
		pr_err("[%s]: invalid input\n", __func__);
		return -EPERM;
	}

	pr_err("%s: handle %d/dmabuf %p\n", __func__, handle, dma_buf);

	/* Increment ref count for this dma_buf. */
	get_dma_buf(dma_buf);

	*dmabuf = dma_buf;

	return 0;
}
EXPORT_SYMBOL_GPL(vc_sm_cma_export_dmabuf);
#endif

/*
 *   Register the driver with device tree
 */

static const struct of_device_id bcm2835_vc_sm_cma_of_match[] = {
	{.compatible = "raspberrypi,bcm2835-vc-sm-cma",},
	{ /* sentinel */ },
};

MODULE_DEVICE_TABLE(of, bcm2835_vcsm_cma_of_match);

static struct platform_driver bcm2835_vcsm_cma_driver = {
	.probe = bcm2835_vc_sm_cma_probe,
	.remove = bcm2835_vc_sm_cma_remove,
	.driver = {
		   .name = DRIVER_NAME,
		   .owner = THIS_MODULE,
		   .of_match_table = bcm2835_vc_sm_cma_of_match,
		   },
};

module_platform_driver(bcm2835_vcsm_cma_driver);

MODULE_AUTHOR("Dave Stevenson");
MODULE_DESCRIPTION("VideoCore CMA Shared Memory Driver");
MODULE_LICENSE("GPL v2");
