/* SPDX-License-Identifier: GPL-2.0 */

/*
 * VideoCore Shared Memory CMA allocator
 *
 * Copyright: 2018, Raspberry Pi (Trading) Ltd
 *
 * Based on the Android ION allocator
 * Copyright (C) Linaro 2012
 * Author: <benjamin.gaignard@linaro.org> for ST-Ericsson.
 *
 */

#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/cma.h>
#include <linux/scatterlist.h>

#include "vc_sm.h"
#include "vc_sm_cma.h"

/* CMA heap operations functions */
int vc_sm_cma_buffer_allocate(struct cma *cma_heap, struct vc_sm_buffer *buffer,
			      unsigned long len)
{
	/* len should already be page aligned */
	unsigned long num_pages = len / PAGE_SIZE;
	struct sg_table *table;
	struct page *pages;
	int ret;

	pages = cma_alloc(cma_heap, num_pages, 0, GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		goto err;

	ret = sg_alloc_table(table, 1, GFP_KERNEL);
	if (ret)
		goto free_mem;

	sg_set_page(table->sgl, pages, len, 0);

	buffer->priv_virt = pages;
	buffer->sg_table = table;
	buffer->cma_heap = cma_heap;
	return 0;

free_mem:
	kfree(table);
err:
	cma_release(cma_heap, pages, num_pages);
	return -ENOMEM;
}

void vc_sm_cma_buffer_free(struct vc_sm_buffer *buffer)
{
	struct cma *cma_heap = buffer->cma_heap;
	struct page *pages = buffer->priv_virt;

	/* release memory */
	if (cma_heap)
		cma_release(cma_heap, pages, buffer->size / PAGE_SIZE);
	/* release sg table */
	if (buffer->sg_table) {
		sg_free_table(buffer->sg_table);
		kfree(buffer->sg_table);
	}
}

void *vc_sm_cma_map_kernel(struct vc_sm_buffer *buffer)
{
	struct scatterlist *sg;
	int i, j;
	void *vaddr = NULL;
	pgprot_t pgprot;
	struct sg_table *table = buffer->sg_table;
	int npages = PAGE_ALIGN(buffer->size) / PAGE_SIZE;
	struct page **pages = vmalloc(sizeof(struct page *) * npages);
	struct page **tmp = pages;

	if (!pages)
		return NULL;

//	if (buffer->flags & ION_FLAG_CACHED)
//		pgprot = PAGE_KERNEL;
//	else
		pgprot = pgprot_writecombine(PAGE_KERNEL);

	for_each_sg(table->sgl, sg, table->nents, i) {
		int npages_this_entry = PAGE_ALIGN(sg->length) / PAGE_SIZE;
		struct page *page = sg_page(sg);

		WARN_ON(i >= npages);
		if (i >= npages)
			break;
		for (j = 0; j < npages_this_entry; j++)
			*(tmp++) = page++;
	}
	if (i < npages)
		vaddr = vmap(pages, npages, VM_MAP, pgprot);
	vfree(pages);

	if (!vaddr)
		return ERR_PTR(-ENOMEM);

	return vaddr;
}

void vc_sm_cma_unmap_kernel(struct vc_sm_buffer *buffer)
{
	vunmap(buffer->vaddr);
}

int vc_sm_cma_map_user(struct vc_sm_buffer *buffer,
		       struct vm_area_struct *vma)
{
	struct sg_table *table = buffer->sg_table;
	unsigned long addr = vma->vm_start;
	unsigned long offset = vma->vm_pgoff * PAGE_SIZE;
	struct scatterlist *sg;
	int i;
	int ret;

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
			return ret;
		addr += len;
		if (addr >= vma->vm_end)
			return 0;
	}
	return 0;
}

int __vc_sm_cma_add_heaps(struct cma *cma, void *priv)
{
	struct cma **heap = (struct cma **)priv;
	const char *name = cma_get_name(cma);

	if (!(*heap)) {
		pr_debug("%s: Adding cma heap %s (start %lX, size %lu) for use by vcsm\n",
			 __func__, name, (unsigned long int)cma_get_base(cma),
			 cma_get_size(cma));
		*heap = cma;
	} else {
		pr_err("%s: Ignoring heap %s as already set\n",
		       __func__, name);
	}

	return 0;
}

int vc_sm_cma_add_heaps(struct cma **cma_heap)
{
	cma_for_each_area(__vc_sm_cma_add_heaps, cma_heap);
	return 0;
}
