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
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

int vc_sm_cma_buffer_allocate(struct cma *cma_heap, struct vc_sm_buffer *buffer,
			      unsigned long len);
void vc_sm_cma_buffer_free(struct vc_sm_buffer *buffer);
void *vc_sm_cma_map_kernel(struct vc_sm_buffer *buffer);
void vc_sm_cma_unmap_kernel(struct vc_sm_buffer *buffer);
int vc_sm_cma_map_user(struct vc_sm_buffer *buffer,
		       struct vm_area_struct *vma);

int vc_sm_cma_add_heaps(struct cma **cma_heap);
