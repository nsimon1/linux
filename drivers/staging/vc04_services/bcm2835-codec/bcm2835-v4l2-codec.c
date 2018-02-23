/*
 * A v4l2-mem2mem device that wraps the video codec MMAL component.
 *
 * Copyright 2018 Raspberry Pi (Trading) Ltd.
 * Author: Dave Stevenson (dave.stevenson@raspberrypi.org)
 *
 * Loosely based on the vim2m virtual driver by Pawel Osciak
 * Copyright (c) 2009-2010 Samsung Electronics Co., Ltd.
 * Pawel Osciak, <pawel@osciak.com>
 * Marek Szyprowski, <m.szyprowski@samsung.com>
 *
 * Whilst this driver uses the v4l2_mem2mem framework, it does not need the
 * scheduling aspects, so will always take the buffers, pass them to the VPU,
 * and then signal the job as complete.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version
 */
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/of_platform.h>
//#include <linux/platform_device.h>
#include <linux/syscalls.h>

#include <media/v4l2-mem2mem.h>
#include <media/v4l2-device.h>
#include <media/v4l2-ioctl.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-event.h>
#include <media/videobuf2-dma-contig.h>

#include "mmal-msg.h"
#include "mmal-encodings.h"
#include "mmal-parameters.h"
#include "mmal-vchiq.h"

MODULE_DESCRIPTION("BCM2835 codec V4L2 driver");
MODULE_AUTHOR("Dave Stevenson, <dave.stevenson@raspberrypi.org>");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.1");

static unsigned debug;
module_param(debug, uint, 0644);
MODULE_PARM_DESC(debug, "activates debug info");

#define BCM2835_V4L2_CODEC_MODULE_NAME "bcm2835-v4l2-codec"

#define MIN_W 32
#define MIN_H 32
#define MAX_W 1920
#define MAX_H 1088
#define DIM_ALIGN_MASK 7 /* 8-byte alignment for line length */

/* Flags that indicate a format can be used for capture/output */
#define MEM2MEM_CAPTURE	(1 << 0)
#define MEM2MEM_OUTPUT	(1 << 1)

#define MEM2MEM_NAME		"bcm2835_codec"

/* Per queue */
#define MEM2MEM_DEF_NUM_BUFS	VIDEO_MAX_FRAME

/* Default transaction time in msec */
#define MEM2MEM_DEF_TRANSTIME	400

#define dprintk(dev, fmt, arg...) \
	v4l2_dbg(1, debug, &dev->v4l2_dev, "%s: " fmt, __func__, ## arg)


struct bcm2835_codec_fmt {
	u32	fourcc;
	int	depth;
	int	bytesperline_align;
	u32	flags;
	u32	mmal_fmt;
	bool	decode_only;
};

/* Supported raw pixel formats. */
static struct bcm2835_codec_fmt raw_formats[] = {
	{
		.fourcc	= V4L2_PIX_FMT_YUV420,
		.depth	= 8,
		.bytesperline_align = 32,
		.flags = 0,
		.mmal_fmt = MMAL_ENCODING_I420,
	},
};

/* Supported encoded formats. Those supported for both encode and decode
 * must come first, with those only supported for decode coming after (there
 * are no formats supported for encode only).
 */
static struct bcm2835_codec_fmt encoded_formats[] = {
	{
		.fourcc	= V4L2_PIX_FMT_H264,
		.depth	= 0,
		.flags = V4L2_FMT_FLAG_COMPRESSED,
		.mmal_fmt = MMAL_ENCODING_H264,
		.decode_only = false,
	}, {
		.fourcc	= V4L2_PIX_FMT_MJPEG,
		.depth	= 0,
		.flags = V4L2_FMT_FLAG_COMPRESSED,
		.mmal_fmt = MMAL_ENCODING_MJPEG,
		.decode_only = false,
	}, {
		.fourcc	= V4L2_PIX_FMT_MPEG4,
		.depth	= 0,
		.flags = V4L2_FMT_FLAG_COMPRESSED,
		.mmal_fmt = MMAL_ENCODING_MP4V,
		.decode_only = true,
	}, {
		.fourcc	= V4L2_PIX_FMT_H263,
		.depth	= 0,
		.flags = V4L2_FMT_FLAG_COMPRESSED,
		.mmal_fmt = MMAL_ENCODING_H263,
		.decode_only = true,
	}, {
		.fourcc	= V4L2_PIX_FMT_MPEG2,
		.depth	= 0,
		.flags = V4L2_FMT_FLAG_COMPRESSED,
		.mmal_fmt = MMAL_ENCODING_MP2V,
		.decode_only = true,
	},
};

struct bcm2835_codec_fmt_list {
	struct bcm2835_codec_fmt *list;
	unsigned int num_entries;
};

#define RAW_LIST	0
#define ENCODED_LIST	1

struct bcm2835_codec_fmt_list formats[] = {
	{
		.list = raw_formats,
		.num_entries = ARRAY_SIZE(raw_formats),
	}, {
		.list = encoded_formats,
		.num_entries = ARRAY_SIZE(encoded_formats),
	},
};

/* Per-queue, driver-specific private data */
struct bcm2835_codec_q_data {
	unsigned int		width;
	unsigned int		height;
	unsigned int		bytesperline;
	unsigned int		sizeimage;
	unsigned int		sequence;
	struct bcm2835_codec_fmt	*fmt;
};

enum {
	V4L2_M2M_SRC = 0,
	V4L2_M2M_DST = 1,
};

static inline struct bcm2835_codec_fmt_list *get_format_list(bool decode,
							     bool capture)
{
	return 	decode ^ capture ? &formats[ENCODED_LIST] : &formats[RAW_LIST];

}

static struct bcm2835_codec_fmt *get_default_format(bool decode, bool capture)
{
	return &get_format_list(decode, capture)->list[0];

}
static struct bcm2835_codec_fmt *find_format(struct v4l2_format *f, bool decode,
					     bool capture)
{
	struct bcm2835_codec_fmt *fmt;
	unsigned int k;
	struct bcm2835_codec_fmt_list *fmts = get_format_list(decode, capture);

	for (k = 0; k < fmts->num_entries; k++) {
		fmt = &fmts->list[k];
		if (fmt->fourcc == f->fmt.pix.pixelformat)
			break;
	}

	/* Some formats are only supported for decoding, not encoding. */
	if (!decode && fmts->list[k].decode_only)
		return NULL;

	if (k == fmts->num_entries)
		return NULL;

	return &fmts->list[k];
}

struct bcm2835_codec_dev {
	struct platform_device *pdev;

	/* v4l2 devices */
	struct v4l2_device	v4l2_dev;
	struct video_device	vfd;
	struct mutex		dev_mutex;
	atomic_t		num_inst;

	/* allocated mmal instance and components */
	bool			decode;	 /* Is this instance a decoder? */
	struct vchiq_mmal_instance	*instance;

	struct {
		/* number of frames remaining which driver should capture */
		unsigned int  frame_count;
		/* last frame completion */
		struct completion  frame_cmplt;

	} capture;
	struct v4l2_m2m_dev	*m2m_dev;
};


struct bcm2835_codec_ctx {
	struct v4l2_fh		fh;
	struct bcm2835_codec_dev	*dev;

	struct v4l2_ctrl_handler hdl;

	struct vchiq_mmal_component  *component;
	bool component_enabled;

	enum v4l2_colorspace	colorspace;
	enum v4l2_ycbcr_encoding ycbcr_enc;
	enum v4l2_xfer_func	xfer_func;
	enum v4l2_quantization	quant;

	/* Source and destination queue data */
	struct bcm2835_codec_q_data   q_data[2];

	bool aborting;
	int num_ip_buffers;
	int num_op_buffers;
};

static inline struct bcm2835_codec_ctx *file2ctx(struct file *file)
{
	return container_of(file->private_data, struct bcm2835_codec_ctx, fh);
}

static struct bcm2835_codec_q_data *get_q_data(struct bcm2835_codec_ctx *ctx,
					       enum v4l2_buf_type type)
{
	switch (type) {
	case V4L2_BUF_TYPE_VIDEO_OUTPUT:
		return &ctx->q_data[V4L2_M2M_SRC];
	case V4L2_BUF_TYPE_VIDEO_CAPTURE:
		return &ctx->q_data[V4L2_M2M_DST];
	default:
		BUG();
	}
	return NULL;
}

static struct vchiq_mmal_port *get_port_data(struct bcm2835_codec_ctx *ctx,
					     enum v4l2_buf_type type)
{
	switch (type) {
	case V4L2_BUF_TYPE_VIDEO_OUTPUT:
		return &ctx->component->input[0];
	case V4L2_BUF_TYPE_VIDEO_CAPTURE:
		return &ctx->component->output[0];
	default:
		BUG();
	}
	return NULL;
}

/*
 * mem2mem callbacks
 */

/**
 * job_ready() - check whether an instance is ready to be scheduled to run
 */
static int job_ready(void *priv)
{
	struct bcm2835_codec_ctx *ctx = priv;

	if (!v4l2_m2m_num_src_bufs_ready(ctx->fh.m2m_ctx) &&
	    !v4l2_m2m_num_dst_bufs_ready(ctx->fh.m2m_ctx)) {
		v4l2_dbg(1, debug, &ctx->dev->v4l2_dev,
			 "Not enough buffers available\n");
		return 0;
	}

	return 1;
}

static void job_abort(void *priv)
{
	struct bcm2835_codec_ctx *ctx = priv;

	v4l2_dbg(1, debug, &ctx->dev->v4l2_dev, "%s\n", __func__);
	/* Will cancel the transaction in the next interrupt handler */
	ctx->aborting = 1;
}

static void setup_mmal_port_format(struct bcm2835_codec_q_data *q_data,
				   struct vchiq_mmal_port *port)
{
	port->format.encoding = q_data->fmt->mmal_fmt;
	port->es.video.width = ALIGN(q_data->width, 32);
	port->es.video.height = ALIGN(q_data->height, 16);
	port->es.video.crop.x = 0;
	port->es.video.crop.y = 0;
	port->es.video.crop.width = q_data->width;
	port->es.video.crop.height = q_data->height;
	port->es.video.frame_rate.num = 0;
	port->es.video.frame_rate.den = 1;
};

static void ip_buffer_cb(struct vchiq_mmal_instance *instance,
			 struct vchiq_mmal_port *port, int status,
			 struct mmal_buffer *mmal_buf)
{
	struct bcm2835_codec_ctx *ctx = port->cb_ctx/*, *curr_ctx*/;
	struct m2m_mmal_buffer *buf =
			container_of(mmal_buf, struct m2m_mmal_buffer, mmal);

	v4l2_err(&ctx->dev->v4l2_dev, "%s: length %lu, flags %x\n", __func__,
		 mmal_buf->length, mmal_buf->mmal_flags);

	if (status != 0) {
		/* error in transfer */
		if (buf) {
			/* there was a buffer with the error so return it */
			v4l2_err(&ctx->dev->v4l2_dev, "%s: status is %d - ERROR\n",
				 __func__, status);
			vb2_buffer_done(&buf->m2m.vb.vb2_buf,
					VB2_BUF_STATE_ERROR);
		}
		return;
	}

	v4l2_err(&ctx->dev->v4l2_dev, "%s: no error. Return buffer %p\n",
		 __func__, &buf->m2m.vb.vb2_buf);
	vb2_buffer_done(&buf->m2m.vb.vb2_buf, VB2_BUF_STATE_DONE);

	ctx->num_ip_buffers++;
	v4l2_err(&ctx->dev->v4l2_dev, "%s: done\n", __func__);
}

static void op_buffer_cb(struct vchiq_mmal_instance *instance,
			 struct vchiq_mmal_port *port, int status,
			 struct mmal_buffer *mmal_buf)
{
	struct bcm2835_codec_ctx *ctx = port->cb_ctx;

	v4l2_err(&ctx->dev->v4l2_dev, "%s: length %lu, flags %x\n", __func__,
		 mmal_buf->length, mmal_buf->mmal_flags);

	v4l2_dbg(1, debug, &ctx->dev->v4l2_dev,
		 "%s: status:%d, buf:%p, length:%lu, flags %u, pts %lld\n",
		 __func__, status, NULL, mmal_buf->length, mmal_buf->mmal_flags,
		 mmal_buf->pts);

	if (status != 0) {
		/* error in transfer */
		if (mmal_buf->vb2) {
			/* there was a buffer with the error so return it */
			vb2_buffer_done(&mmal_buf->vb2->vb2_buf,
					VB2_BUF_STATE_ERROR);
		} else {
			v4l2_dbg(1, debug, &ctx->dev->v4l2_dev,
				 "%s: Error (%d) but no vb2 buf!!!\n", __func__,
				 status);
		}
		return;
	}

	if (mmal_buf->length == 0) {
		/* stream ended */
		if (mmal_buf->vb2) {
			/* this should only ever happen if the port is
			 * disabled and there are buffers still queued
			 */
			pr_debug("%s: Empty buffer", __func__);
			vb2_buffer_done(&mmal_buf->vb2->vb2_buf,
					VB2_BUF_STATE_ERROR);
		} else {
			/* signal frame completion */
			//complete(&dev->capture.frame_cmplt);
			v4l2_dbg(1, debug, &ctx->dev->v4l2_dev,
				 "%s: Empty buffer but no vb2 buf!!!",
				 __func__);
		}
		return;
	}

	mmal_buf->vb2->vb2_buf.timestamp = mmal_buf->pts;

	vb2_set_plane_payload(&mmal_buf->vb2->vb2_buf, 0, mmal_buf->length);
	if (mmal_buf->mmal_flags & MMAL_BUFFER_HEADER_FLAG_KEYFRAME)
		mmal_buf->vb2->flags |= V4L2_BUF_FLAG_KEYFRAME;

	vb2_buffer_done(&mmal_buf->vb2->vb2_buf, VB2_BUF_STATE_DONE);
	ctx->num_op_buffers++;
}

/* vb2_to_mmal_buffer() - converts vb2 buffer header to MMAL
 *
 * Copies all the required fields from a VB2 buffer to the MMAL buffer header,
 * ready for sending to the VPU.
 */
static void vb2_to_mmal_buffer(struct m2m_mmal_buffer *buf)
{
	buf->mmal.mmal_flags = 0;
	if (buf->mmal.vb2->flags & V4L2_BUF_FLAG_KEYFRAME)
		buf->mmal.mmal_flags |= MMAL_BUFFER_HEADER_FLAG_KEYFRAME;

	buf->mmal.length = buf->mmal.vb2->vb2_buf.planes[0].bytesused;
	buf->mmal.pts = buf->mmal.vb2->vb2_buf.timestamp;
	buf->mmal.dts = MMAL_TIME_UNKNOWN;
}

/* device_run() - prepares and starts the device
 *
 * This simulates all the immediate preparations required before starting
 * a device. This will be called by the framework when it decides to schedule
 * a particular instance.
 */
static void device_run(void *priv)
{
	struct bcm2835_codec_ctx *ctx = priv;
	struct bcm2835_codec_dev *dev = ctx->dev;
	struct vb2_v4l2_buffer *src_buf, *dst_buf;
	struct m2m_mmal_buffer *src_m2m_buf, *dst_m2m_buf;
	struct v4l2_m2m_buffer *m2m;
	int ret;

	v4l2_dbg(1, debug, &ctx->dev->v4l2_dev, "%s: off we go\n", __func__);

	src_buf = v4l2_m2m_buf_remove(&ctx->fh.m2m_ctx->out_q_ctx);
	if (src_buf) {
		m2m = container_of(src_buf, struct v4l2_m2m_buffer, vb);
		src_m2m_buf = container_of(m2m, struct m2m_mmal_buffer, m2m);
		vb2_to_mmal_buffer(src_m2m_buf);

		ret = vchiq_mmal_submit_buffer(dev->instance,
					       &ctx->component->input[0],
					       &src_m2m_buf->mmal);
		if (ret)
			v4l2_err(&ctx->dev->v4l2_dev, "%s: Failed submitting ip buffer\n",
				 __func__);
	}

	dst_buf = v4l2_m2m_buf_remove(&ctx->fh.m2m_ctx->cap_q_ctx);
	if (dst_buf) {
		m2m = container_of(dst_buf, struct v4l2_m2m_buffer, vb);
		dst_m2m_buf = container_of(m2m, struct m2m_mmal_buffer, m2m);
		vb2_to_mmal_buffer(dst_m2m_buf);

		ret = vchiq_mmal_submit_buffer(dev->instance,
					       &ctx->component->output[0],
					       &dst_m2m_buf->mmal);
		if (ret)
			v4l2_err(&ctx->dev->v4l2_dev, "%s: Failed submitting op buffer\n",
				 __func__);
	}

	v4l2_dbg(1, debug, &ctx->dev->v4l2_dev, "%s: Submitted src %p, dst %p\n",
		 __func__, src_m2m_buf, dst_m2m_buf);

	/* Complete the job here. */
	v4l2_m2m_job_finish(ctx->dev->m2m_dev, ctx->fh.m2m_ctx);
}

/*
 * video ioctls
 */
static int vidioc_querycap(struct file *file, void *priv,
			   struct v4l2_capability *cap)
{
	strncpy(cap->driver, MEM2MEM_NAME, sizeof(cap->driver) - 1);
	strncpy(cap->card, MEM2MEM_NAME, sizeof(cap->card) - 1);
	snprintf(cap->bus_info, sizeof(cap->bus_info),
			"platform:%s", MEM2MEM_NAME);
	cap->device_caps = V4L2_CAP_VIDEO_M2M | V4L2_CAP_STREAMING;
	cap->capabilities = cap->device_caps | V4L2_CAP_DEVICE_CAPS;
	return 0;
}

static int enum_fmt(struct v4l2_fmtdesc *f, bool decode, bool capture)
{
	struct bcm2835_codec_fmt *fmt;
	struct bcm2835_codec_fmt_list *fmts = get_format_list(decode, capture);

	if (f->index < fmts->num_entries) {
		/* Format found */
		/* Check format isn't a decode only format when encoding */
		if (!decode &&
		    fmts->list[f->index].flags & V4L2_FMT_FLAG_COMPRESSED &&
		    fmts->list[f->index].decode_only)
			return -EINVAL;

		fmt = &fmts->list[f->index];
		f->pixelformat = fmt->fourcc;
		f->flags = fmt->flags;
		return 0;
	}

	/* Format not found */
	return -EINVAL;
}

static int vidioc_enum_fmt_vid_cap(struct file *file, void *priv,
				   struct v4l2_fmtdesc *f)
{
	struct bcm2835_codec_ctx *ctx = file2ctx(file);
	return enum_fmt(f, ctx->dev->decode, true);
}

static int vidioc_enum_fmt_vid_out(struct file *file, void *priv,
				   struct v4l2_fmtdesc *f)
{
	struct bcm2835_codec_ctx *ctx = file2ctx(file);
	return enum_fmt(f, ctx->dev->decode, false);
}

static int vidioc_g_fmt(struct bcm2835_codec_ctx *ctx, struct v4l2_format *f)
{
	struct vb2_queue *vq;
	struct bcm2835_codec_q_data *q_data;

	vq = v4l2_m2m_get_vq(ctx->fh.m2m_ctx, f->type);
	if (!vq)
		return -EINVAL;

	q_data = get_q_data(ctx, f->type);

	f->fmt.pix.width	= q_data->width;
	f->fmt.pix.height	= q_data->height;
	f->fmt.pix.field	= V4L2_FIELD_NONE;
	f->fmt.pix.pixelformat	= q_data->fmt->fourcc;
	f->fmt.pix.bytesperline	= q_data->bytesperline;
	f->fmt.pix.sizeimage	= q_data->sizeimage;
	f->fmt.pix.colorspace	= ctx->colorspace;
	f->fmt.pix.xfer_func	= ctx->xfer_func;
	f->fmt.pix.ycbcr_enc	= ctx->ycbcr_enc;
	f->fmt.pix.quantization	= ctx->quant;

	return 0;
}

static int vidioc_g_fmt_vid_out(struct file *file, void *priv,
				struct v4l2_format *f)
{
	return vidioc_g_fmt(file2ctx(file), f);
}

static int vidioc_g_fmt_vid_cap(struct file *file, void *priv,
				struct v4l2_format *f)
{
	return vidioc_g_fmt(file2ctx(file), f);
}

static int vidioc_try_fmt(struct v4l2_format *f, struct bcm2835_codec_fmt *fmt)
{
	/* V4L2 specification suggests the driver corrects the format struct
	 * if any of the dimensions is unsupported */
	if (f->fmt.pix.height < MIN_H)
		f->fmt.pix.height = MIN_H;
	else if (f->fmt.pix.height > MAX_H)
		f->fmt.pix.height = MAX_H;

	if (f->fmt.pix.width < MIN_W)
		f->fmt.pix.width = MIN_W;
	else if (f->fmt.pix.width > MAX_W)
		f->fmt.pix.width = MAX_W;

	f->fmt.pix.width &= ~DIM_ALIGN_MASK;
	if (!fmt->flags & V4L2_FMT_FLAG_COMPRESSED)
		f->fmt.pix.bytesperline =
				ALIGN((f->fmt.pix.width * fmt->depth) >> 3,
				      fmt->bytesperline_align);
	else
		f->fmt.pix.bytesperline = 0;
	f->fmt.pix.sizeimage = f->fmt.pix.height * f->fmt.pix.bytesperline;
	f->fmt.pix.field = V4L2_FIELD_NONE;

	return 0;
}

static int vidioc_try_fmt_vid_cap(struct file *file, void *priv,
				  struct v4l2_format *f)
{
	struct bcm2835_codec_fmt *fmt;
	struct bcm2835_codec_ctx *ctx = file2ctx(file);

	fmt = find_format(f, ctx->dev->decode, true);
	if (!fmt) {
		f->fmt.pix.pixelformat = get_default_format(ctx->dev->decode,
							    true)->fourcc;
		fmt = find_format(f, ctx->dev->decode, true);
	}

	f->fmt.pix.colorspace = ctx->colorspace;
	f->fmt.pix.xfer_func = ctx->xfer_func;
	f->fmt.pix.ycbcr_enc = ctx->ycbcr_enc;
	f->fmt.pix.quantization = ctx->quant;

	return vidioc_try_fmt(f, fmt);
}

static int vidioc_try_fmt_vid_out(struct file *file, void *priv,
				  struct v4l2_format *f)
{
	struct bcm2835_codec_fmt *fmt;
	struct bcm2835_codec_ctx *ctx = file2ctx(file);

	fmt = find_format(f, ctx->dev->decode, false);
	if (!fmt) {
		f->fmt.pix.pixelformat = get_default_format(ctx->dev->decode,
							    false)->fourcc;
		fmt = find_format(f, ctx->dev->decode, false);
	}

	if (!f->fmt.pix.colorspace)
		f->fmt.pix.colorspace = V4L2_COLORSPACE_REC709;

	return vidioc_try_fmt(f, fmt);
}

static int vidioc_s_fmt(struct bcm2835_codec_ctx *ctx, struct v4l2_format *f)
{
	struct bcm2835_codec_q_data *q_data;
	struct vb2_queue *vq;
	struct vchiq_mmal_port *port;
	int ret;

	vq = v4l2_m2m_get_vq(ctx->fh.m2m_ctx, f->type);
	if (!vq)
		return -EINVAL;

	q_data = get_q_data(ctx, f->type);
	if (!q_data)
		return -EINVAL;

	port = get_port_data(ctx, vq->type);
	if (!port)
		return -EINVAL;

	if (vb2_is_busy(vq)) {
		v4l2_err(&ctx->dev->v4l2_dev, "%s queue busy\n", __func__);
		return -EBUSY;
	}

	q_data->fmt		= find_format(f, ctx->dev->decode,
					      f->type == V4L2_BUF_TYPE_VIDEO_CAPTURE);
	q_data->width		= f->fmt.pix.width;
	q_data->height		= f->fmt.pix.height;

	setup_mmal_port_format(q_data, port);

	ret = vchiq_mmal_port_set_format(ctx->dev->instance, port);
	if (ret)
		v4l2_err(&ctx->dev->v4l2_dev, "%s: Failed vchiq_mmal_port_set_format on port, ret %d\n",
			 __func__, ret);
	q_data->sizeimage	= port->minimum_buffer.size;


	dprintk(ctx->dev,
		"Setting format for type %d, wxh: %dx%d, fmt: %d\n",
		f->type, q_data->width, q_data->height, q_data->fmt->fourcc);

	return 0;
}

static int vidioc_s_fmt_vid_cap(struct file *file, void *priv,
				struct v4l2_format *f)
{
	int ret;

	ret = vidioc_try_fmt_vid_cap(file, priv, f);
	if (ret)
		return ret;

	return vidioc_s_fmt(file2ctx(file), f);
}

static int vidioc_s_fmt_vid_out(struct file *file, void *priv,
				struct v4l2_format *f)
{
	struct bcm2835_codec_ctx *ctx = file2ctx(file);
	int ret;

	ret = vidioc_try_fmt_vid_out(file, priv, f);
	if (ret)
		return ret;

	ret = vidioc_s_fmt(file2ctx(file), f);
	if (!ret) {
		ctx->colorspace = f->fmt.pix.colorspace;
		ctx->xfer_func = f->fmt.pix.xfer_func;
		ctx->ycbcr_enc = f->fmt.pix.ycbcr_enc;
		ctx->quant = f->fmt.pix.quantization;
	}
	return ret;
}

static int bcm2835_codec_s_ctrl(struct v4l2_ctrl *ctrl)
{
	struct bcm2835_codec_ctx *ctx =
		container_of(ctrl->handler, struct bcm2835_codec_ctx, hdl);
	int ret;

	switch (ctrl->id) {
	case V4L2_CID_MPEG_VIDEO_BITRATE:
		v4l2_err(&ctx->dev->v4l2_dev, "Setting bitrate to %d\n",
			 ctrl->val);
		ret = vchiq_mmal_port_parameter_set(ctx->dev->instance,
						    &ctx->component->output[0],
						    MMAL_PARAMETER_VIDEO_BIT_RATE,
						    &ctrl->val,
						    sizeof(ctrl->val));
		break;

	case V4L2_CID_MPEG_VIDEO_BITRATE_MODE: {
		u32 bitrate_mode;

		v4l2_err(&ctx->dev->v4l2_dev, "Setting bitrate mode to %d\n",
			 ctrl->val);

		switch (ctrl->val) {
		default:
		case V4L2_MPEG_VIDEO_BITRATE_MODE_VBR:
			bitrate_mode = MMAL_VIDEO_RATECONTROL_VARIABLE;
			break;
		case V4L2_MPEG_VIDEO_BITRATE_MODE_CBR:
			bitrate_mode = MMAL_VIDEO_RATECONTROL_CONSTANT;
			break;
		}

		ret = vchiq_mmal_port_parameter_set(ctx->dev->instance,
						    &ctx->component->output[0],
						    MMAL_PARAMETER_RATECONTROL,
						    &bitrate_mode,
						    sizeof(bitrate_mode));
		break;
	}
	case V4L2_CID_MPEG_VIDEO_REPEAT_SEQ_HEADER:
		v4l2_err(&ctx->dev->v4l2_dev, "Setting repeat seq header to %d\n",
			 ctrl->val);
		ret = vchiq_mmal_port_parameter_set(ctx->dev->instance,
						    &ctx->component->output[0],
						    MMAL_PARAMETER_VIDEO_ENCODE_INLINE_HEADER,
						    &ctrl->val,
						    sizeof(ctrl->val));
		break;

	case V4L2_CID_MPEG_VIDEO_H264_I_PERIOD:
		v4l2_err(&ctx->dev->v4l2_dev, "Setting intra-I period to %d\n",
			 ctrl->val);
		ret = vchiq_mmal_port_parameter_set(ctx->dev->instance,
						    &ctx->component->output[0],
						    MMAL_PARAMETER_INTRAPERIOD,
						    &ctrl->val,
						    sizeof(ctrl->val));
		break;

	default:
		v4l2_err(&ctx->dev->v4l2_dev, "Invalid control\n");
		return -EINVAL;
	}

	if (ret)
		v4l2_err(&ctx->dev->v4l2_dev, "Failed setting ctrl %08x, ret %d\n",
			 ctrl->id, ret);
	return ret ? -EINVAL : 0;
}

static const struct v4l2_ctrl_ops bcm2835_codec_ctrl_ops = {
	.s_ctrl = bcm2835_codec_s_ctrl,
};


static const struct v4l2_ioctl_ops bcm2835_codec_ioctl_ops = {
	.vidioc_querycap	= vidioc_querycap,

	.vidioc_enum_fmt_vid_cap = vidioc_enum_fmt_vid_cap,
	.vidioc_g_fmt_vid_cap	= vidioc_g_fmt_vid_cap,
	.vidioc_try_fmt_vid_cap	= vidioc_try_fmt_vid_cap,
	.vidioc_s_fmt_vid_cap	= vidioc_s_fmt_vid_cap,

	.vidioc_enum_fmt_vid_out = vidioc_enum_fmt_vid_out,
	.vidioc_g_fmt_vid_out	= vidioc_g_fmt_vid_out,
	.vidioc_try_fmt_vid_out	= vidioc_try_fmt_vid_out,
	.vidioc_s_fmt_vid_out	= vidioc_s_fmt_vid_out,

	.vidioc_reqbufs		= v4l2_m2m_ioctl_reqbufs,
	.vidioc_querybuf	= v4l2_m2m_ioctl_querybuf,
	.vidioc_qbuf		= v4l2_m2m_ioctl_qbuf,
	.vidioc_dqbuf		= v4l2_m2m_ioctl_dqbuf,
	.vidioc_prepare_buf	= v4l2_m2m_ioctl_prepare_buf,
	.vidioc_create_bufs	= v4l2_m2m_ioctl_create_bufs,
	.vidioc_expbuf		= v4l2_m2m_ioctl_expbuf,

	.vidioc_streamon	= v4l2_m2m_ioctl_streamon,
	.vidioc_streamoff	= v4l2_m2m_ioctl_streamoff,

	.vidioc_subscribe_event = v4l2_ctrl_subscribe_event,
	.vidioc_unsubscribe_event = v4l2_event_unsubscribe,
};


/*
 * Queue operations
 */

static int bcm2835_codec_queue_setup(struct vb2_queue *vq,
				unsigned int *nbuffers, unsigned int *nplanes,
				unsigned int sizes[], struct device *alloc_devs[])
{
	struct bcm2835_codec_ctx *ctx = vb2_get_drv_priv(vq);
	struct bcm2835_codec_q_data *q_data;
	struct vchiq_mmal_port *port;
	unsigned int size;

	q_data = get_q_data(ctx, vq->type);
	port = get_port_data(ctx, vq->type);

	size = port->minimum_buffer.size;

	if (*nplanes)
		return sizes[0] < size ? -EINVAL : 0;

	*nplanes = 1;

	sizes[0] = size;
	port->current_buffer.size = size;

	if (*nbuffers < port->minimum_buffer.num)
		*nbuffers = port->minimum_buffer.num;
	port->current_buffer.num = *nbuffers;


	dprintk(ctx->dev, "get %d buffer(s) of size %d each.\n", *nbuffers, size);

	return 0;
}

static int bcm2835_codec_buf_init(struct vb2_buffer *vb)
{
	struct bcm2835_codec_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);
	struct vb2_v4l2_buffer *vb2 = to_vb2_v4l2_buffer(vb);
	struct v4l2_m2m_buffer *m2m = container_of(vb2, struct v4l2_m2m_buffer, vb);
	struct m2m_mmal_buffer *buf = container_of(m2m, struct m2m_mmal_buffer, m2m);

	v4l2_dbg(1, debug, &ctx->dev->v4l2_dev, "%s: ctx:%p, vb %p\n",
		 __func__, ctx, vb);
	buf->mmal.buffer = vb2_plane_vaddr(&buf->m2m.vb.vb2_buf, 0);
	buf->mmal.buffer_size = vb2_plane_size(&buf->m2m.vb.vb2_buf, 0);
	buf->mmal.vb2 = &buf->m2m.vb;

	mmal_vchi_buffer_init(ctx->dev->instance, &buf->mmal);

	return 0;
}

static int bcm2835_codec_buf_prepare(struct vb2_buffer *vb)
{
	struct bcm2835_codec_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);
	struct bcm2835_codec_q_data *q_data;
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);
	struct v4l2_m2m_buffer *m2m = container_of(vbuf, struct v4l2_m2m_buffer, vb);
	struct m2m_mmal_buffer *buf = container_of(m2m, struct m2m_mmal_buffer, m2m);
	int ret;

	v4l2_dbg(1, debug, &ctx->dev->v4l2_dev, "%s: type: %d ptr %p\n", __func__, vb->vb2_queue->type, vb);

	q_data = get_q_data(ctx, vb->vb2_queue->type);
	if (V4L2_TYPE_IS_OUTPUT(vb->vb2_queue->type)) {
		if (vbuf->field == V4L2_FIELD_ANY)
			vbuf->field = V4L2_FIELD_NONE;
		if (vbuf->field != V4L2_FIELD_NONE) {
			dprintk(ctx->dev, "%s field isn't supported\n",
					__func__);
			return -EINVAL;
		}
	}

	if (vb2_plane_size(vb, 0) < q_data->sizeimage) {
		dprintk(ctx->dev, "%s data will not fit into plane (%lu < %lu)\n",
				__func__, vb2_plane_size(vb, 0), (long)q_data->sizeimage);
		return -EINVAL;
	}

	vb2_set_plane_payload(vb, 0, q_data->sizeimage);

#if defined(CONFIG_BCM_VC_SM_CMA)
	/*
	 * Two niggles:
	 * 1 - We want to do this at init, but vb2_core_expbuf checks that the
	 * index < q->num_buffers, and q->num_buffers only gets updated once
	 * all the buffers are allocated.
	 *
	 * 2 - videobuf2 only exposes dmabufs as an fd via vb2_core_expbuf.
	 * Ideally we'd like the struct dma_buf directly, but can't get hold of
	 * it, so have to accept the fd and work with it.
	 */
	if (!buf->mmal.dma_buf) {
		int fd;

		ret = vb2_core_expbuf(vb->vb2_queue, &fd,
				      vb->vb2_queue->type, vb->index, 0,
				      O_CLOEXEC);
		if (ret)
			v4l2_err(&ctx->dev->v4l2_dev, "%s: Failed to expbuf idx %d, ret %d\n",
				 __func__, vb->index, ret);
		buf->mmal.dma_buf = dma_buf_get(fd);
		v4l2_err(&ctx->dev->v4l2_dev, "%s: Given dma_buf fd %d, %p\n",
			 __func__, fd, buf->mmal.dma_buf);
		/*
		 * Release the fd (and the associated refcount) as we now have
		 * a ref to the dma_buf
		 */
		sys_close(fd);
	}
#else
	ret = 0;
#endif

	return ret;
}

static void bcm2835_codec_buf_queue(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);
	struct bcm2835_codec_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);

	v4l2_dbg(1, debug, &ctx->dev->v4l2_dev, "%s: type: %d ptr %p vbuf->flags %u, seq %u, bytesused %u\n",
		__func__, vb->vb2_queue->type, vb, vbuf->flags, vbuf->sequence, vb->planes[0].bytesused);
	v4l2_m2m_buf_queue(ctx->fh.m2m_ctx, vbuf);
}

static void bcm2835_codec_buffer_cleanup(struct vb2_buffer *vb)
{
	struct bcm2835_codec_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);
	struct vb2_v4l2_buffer *vb2 = to_vb2_v4l2_buffer(vb);
	struct v4l2_m2m_buffer *m2m = container_of(vb2, struct v4l2_m2m_buffer, vb);
	struct m2m_mmal_buffer *buf = container_of(m2m, struct m2m_mmal_buffer, m2m);

	v4l2_dbg(1, debug, &ctx->dev->v4l2_dev, "%s: ctx:%p, vb %p\n",
		 __func__, ctx, vb);

	mmal_vchi_buffer_cleanup(&buf->mmal);

#if defined(CONFIG_BCM_VC_SM_CMA)
	if (buf->mmal.dma_buf)
		dma_buf_put(buf->mmal.dma_buf);
#endif
}

static int bcm2835_codec_start_streaming(struct vb2_queue *q, unsigned count)
{
	struct bcm2835_codec_ctx *ctx = vb2_get_drv_priv(q);
	struct bcm2835_codec_dev *dev = ctx->dev;
	struct bcm2835_codec_q_data *q_data = get_q_data(ctx, q->type);
	int ret;

	v4l2_dbg(1, debug, &ctx->dev->v4l2_dev, "%s: type: %d count %d\n", __func__, q->type, count);
	q_data->sequence = 0;

	if (!ctx->component_enabled) {
		ret = vchiq_mmal_component_enable(dev->instance,
						  ctx->component);
		if (ret)
			v4l2_err(&ctx->dev->v4l2_dev, "%s: Failed enabling component, ret %d\n",
				__func__, ret);
		ctx->component_enabled = true;
	}

	if (q->type == V4L2_BUF_TYPE_VIDEO_OUTPUT) {
		ctx->component->input[0].cb_ctx = ctx;
		ret = vchiq_mmal_port_enable(dev->instance,
					     &ctx->component->input[0],
					     ip_buffer_cb);
		if (ret)
			v4l2_err(&ctx->dev->v4l2_dev, "%s: Failed enabling i/p port, ret %d\n",
				__func__, ret);
	} else {
		ctx->component->output[0].cb_ctx = ctx;
		ret = vchiq_mmal_port_enable(dev->instance,
					     &ctx->component->output[0],
					     op_buffer_cb);
		if (ret)
			v4l2_err(&ctx->dev->v4l2_dev, "%s: Failed enabling o/p port, ret %d\n",
				__func__, ret);
	}
	return ret;
}

static void bcm2835_codec_stop_streaming(struct vb2_queue *q)
{
	struct bcm2835_codec_ctx *ctx = vb2_get_drv_priv(q);
	struct bcm2835_codec_dev *dev = ctx->dev;
	struct vb2_v4l2_buffer *vbuf;
	int ret;

	v4l2_dbg(1, debug, &ctx->dev->v4l2_dev, "%s: type: %d - return buffers\n",
		 __func__, q->type);
	for (;;) {
		if (V4L2_TYPE_IS_OUTPUT(q->type))
			vbuf = v4l2_m2m_src_buf_remove(ctx->fh.m2m_ctx);
		else
			vbuf = v4l2_m2m_dst_buf_remove(ctx->fh.m2m_ctx);
		if (vbuf == NULL)
			return;
		v4l2_dbg(1, debug, &ctx->dev->v4l2_dev, "%s: return buffer %p\n",
			 __func__, vbuf);

		v4l2_m2m_buf_done(vbuf, VB2_BUF_STATE_ERROR);
	}

	if (q->type == V4L2_BUF_TYPE_VIDEO_OUTPUT) {
		ret = vchiq_mmal_port_disable(dev->instance,
					     &ctx->component->input[0]);
		if (ret)
			v4l2_err(&ctx->dev->v4l2_dev, "%s: Failed enabling i/p port, ret %d\n",
				 __func__, ret);
	} else {
		ret = vchiq_mmal_port_disable(dev->instance,
					     &ctx->component->output[0]);
		if (ret)
			v4l2_err(&ctx->dev->v4l2_dev, "%s: Failed enabling o/p port, ret %d\n",
				 __func__, ret);
	}

	if (!ctx->component->input[0].enabled &&
	    !ctx->component->output[0].enabled) {
		ret = vchiq_mmal_component_disable(dev->instance,
						  ctx->component);
		if (ret)
			v4l2_err(&ctx->dev->v4l2_dev, "%s: Failed enabling component, ret %d\n",
				__func__, ret);
	}

	v4l2_dbg(1, debug, &ctx->dev->v4l2_dev, "%s: done\n", __func__);
}

static const struct vb2_ops bcm2835_codec_qops = {
	.queue_setup	 = bcm2835_codec_queue_setup,
	.buf_init	 = bcm2835_codec_buf_init,
	.buf_prepare	 = bcm2835_codec_buf_prepare,
	.buf_queue	 = bcm2835_codec_buf_queue,
	.buf_cleanup	 = bcm2835_codec_buffer_cleanup,
	.start_streaming = bcm2835_codec_start_streaming,
	.stop_streaming  = bcm2835_codec_stop_streaming,
	.wait_prepare	 = vb2_ops_wait_prepare,
	.wait_finish	 = vb2_ops_wait_finish,
};

static int queue_init(void *priv, struct vb2_queue *src_vq, struct vb2_queue *dst_vq)
{
	struct bcm2835_codec_ctx *ctx = priv;
	int ret;

	src_vq->type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
	src_vq->io_modes = VB2_MMAP | VB2_USERPTR | VB2_DMABUF;
	src_vq->drv_priv = ctx;
	src_vq->buf_struct_size = sizeof(struct m2m_mmal_buffer);
	src_vq->ops = &bcm2835_codec_qops;
	src_vq->mem_ops = &vb2_dma_contig_memops;
	src_vq->dev = &ctx->dev->pdev->dev;
	src_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	src_vq->lock = &ctx->dev->dev_mutex;

	ret = vb2_queue_init(src_vq);
	if (ret)
		return ret;

	dst_vq->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	dst_vq->io_modes = VB2_MMAP | VB2_USERPTR | VB2_DMABUF;
	dst_vq->drv_priv = ctx;
	dst_vq->buf_struct_size = sizeof(struct m2m_mmal_buffer);
	dst_vq->ops = &bcm2835_codec_qops;
	dst_vq->mem_ops = &vb2_dma_contig_memops;
	dst_vq->dev = &ctx->dev->pdev->dev;
	dst_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	dst_vq->lock = &ctx->dev->dev_mutex;

	return vb2_queue_init(dst_vq);
}

/*
 * File operations
 */
static int bcm2835_codec_open(struct file *file)
{
	struct bcm2835_codec_dev *dev = video_drvdata(file);
	struct bcm2835_codec_ctx *ctx = NULL;
	struct v4l2_ctrl_handler *hdl;
#if defined(CONFIG_BCM_VC_SM_CMA)
	unsigned int enable = 1;
#endif
	int rc = 0;

	if (mutex_lock_interruptible(&dev->dev_mutex))
		return -ERESTARTSYS;
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		rc = -ENOMEM;
		goto open_unlock;
	}

	/* Initialise MMAL stuff first */
	rc = vchiq_mmal_component_init(dev->instance, dev->decode ?
					"ril.video_decode" : "ril.video_encode",
					&ctx->component);
	if (rc < 0)
		return -EINVAL;

#if defined(CONFIG_BCM_VC_SM_CMA)
	vchiq_mmal_port_parameter_set(
			dev->instance,
			&ctx->component->input[0],
			MMAL_PARAMETER_ZERO_COPY,
			&enable, sizeof(enable));
	vchiq_mmal_port_parameter_set(
			dev->instance,
			&ctx->component->output[0],
			MMAL_PARAMETER_ZERO_COPY,
			&enable, sizeof(enable));
#endif
	ctx->q_data[V4L2_M2M_SRC].fmt = get_default_format(dev->decode, false);
	ctx->q_data[V4L2_M2M_SRC].width = 640;
	ctx->q_data[V4L2_M2M_SRC].height = 480;

	ctx->q_data[V4L2_M2M_DST] = ctx->q_data[V4L2_M2M_SRC];
	ctx->q_data[V4L2_M2M_DST].fmt = get_default_format(dev->decode, true);

	ctx->colorspace = V4L2_COLORSPACE_REC709;

	setup_mmal_port_format(&ctx->q_data[V4L2_M2M_SRC],
			       &ctx->component->input[0]);

	setup_mmal_port_format(&ctx->q_data[V4L2_M2M_DST],
			       &ctx->component->output[0]);

	if (!dev->decode)
		ctx->component->output[0].format.bitrate = 10 * 1000 * 1000;

	rc = vchiq_mmal_port_set_format(dev->instance,
					 &ctx->component->input[0]);
	if (rc < 0)
		goto destroy_component;
	ctx->q_data[V4L2_M2M_SRC].sizeimage =
		ctx->component->input[0].minimum_buffer.size;

	rc = vchiq_mmal_port_set_format(dev->instance,
					 &ctx->component->output[0]);
	if (rc < 0)
		goto destroy_component;
	ctx->q_data[V4L2_M2M_DST].sizeimage =
		ctx->component->output[0].minimum_buffer.size;

	/* Initialise V4L2 contexts */
	v4l2_fh_init(&ctx->fh, video_devdata(file));
	file->private_data = &ctx->fh;
	ctx->dev = dev;
	hdl = &ctx->hdl;
	if (!dev->decode) {
		/* Encode controls */
		v4l2_ctrl_handler_init(hdl, 4);

		v4l2_ctrl_new_std_menu(hdl, &bcm2835_codec_ctrl_ops,
				  V4L2_CID_MPEG_VIDEO_BITRATE_MODE,
				  V4L2_MPEG_VIDEO_BITRATE_MODE_CBR, 0,
				  V4L2_MPEG_VIDEO_BITRATE_MODE_VBR);
		v4l2_ctrl_new_std(hdl, &bcm2835_codec_ctrl_ops,
				  V4L2_CID_MPEG_VIDEO_BITRATE,
				  25 * 1000, 25 * 1000 * 1000,
				  25 * 1000, 10 * 1000 * 1000);
		v4l2_ctrl_new_std(hdl, &bcm2835_codec_ctrl_ops,
				  V4L2_CID_MPEG_VIDEO_REPEAT_SEQ_HEADER,
				  0, 1,
				  1, 0);
		v4l2_ctrl_new_std(hdl, &bcm2835_codec_ctrl_ops,
				  V4L2_CID_MPEG_VIDEO_H264_I_PERIOD,
				  0, 0x7FFFFFFF,
				  1, 60);
		//v4l2_ctrl_new_std(hdl, &bcm2835_codec_ctrl_ops,
		//		V4L2_CID_MPEG_VIDEO_H264_LEVEL, 0, 1, 1, 0);
		//v4l2_ctrl_new_std(hdl, &bcm2835_codec_ctrl_ops,
		//		V4L2_CID_MPEG_VIDEO_H264_PROFILE, 0, 1, 1, 0);
		if (hdl->error) {
			rc = hdl->error;
			goto free_ctrl_handler;
		}
		ctx->fh.ctrl_handler = hdl;
		v4l2_ctrl_handler_setup(hdl);
	}

	ctx->fh.m2m_ctx = v4l2_m2m_ctx_init(dev->m2m_dev, ctx, &queue_init);

	if (IS_ERR(ctx->fh.m2m_ctx)) {
		rc = PTR_ERR(ctx->fh.m2m_ctx);

		goto free_ctrl_handler;
	}

	/* Set both queues as buffered as we have buffering in the VPU. That
	 * means that we will be scheduled whenever either an input or output
	 * buffer is available (otherwise one of each are required).
	 */
	v4l2_m2m_set_src_buffered(ctx->fh.m2m_ctx, true);
	v4l2_m2m_set_dst_buffered(ctx->fh.m2m_ctx, true);

	v4l2_fh_add(&ctx->fh);
	atomic_inc(&dev->num_inst);

	v4l2_err(&dev->v4l2_dev, "Created instance: %p, m2m_ctx: %p\n",
		ctx, ctx->fh.m2m_ctx);

	mutex_unlock(&dev->dev_mutex);
	return 0;

free_ctrl_handler:
	v4l2_ctrl_handler_free(hdl);

destroy_component:
	vchiq_mmal_component_finalise(dev->instance, ctx->component);
	kfree(ctx);
open_unlock:
	mutex_unlock(&dev->dev_mutex);
	return rc;
}

static int bcm2835_codec_release(struct file *file)
{
	struct bcm2835_codec_dev *dev = video_drvdata(file);
	struct bcm2835_codec_ctx *ctx = file2ctx(file);

	v4l2_err(&dev->v4l2_dev, "%s: Releasing instance %p\n", __func__, ctx);

	v4l2_fh_del(&ctx->fh);
	v4l2_fh_exit(&ctx->fh);
	v4l2_ctrl_handler_free(&ctx->hdl);
	v4l2_err(&dev->v4l2_dev, "%s: Releasing instance %p - waiting for mutex\n", __func__, ctx);
	mutex_lock(&dev->dev_mutex);
	v4l2_err(&dev->v4l2_dev, "%s: Releasing instance %p - obtained mutex\n", __func__, ctx);
	v4l2_m2m_ctx_release(ctx->fh.m2m_ctx);
	v4l2_err(&dev->v4l2_dev, "%s: Releasing instance %p - ctx_released\n", __func__, ctx);

	vchiq_mmal_component_finalise(dev->instance, ctx->component);

	mutex_unlock(&dev->dev_mutex);
	kfree(ctx);

	atomic_dec(&dev->num_inst);
	v4l2_err(&dev->v4l2_dev, "%s: Releasing instance %p - done\n", __func__, ctx);

	return 0;
}

static const struct v4l2_file_operations bcm2835_codec_fops = {
	.owner		= THIS_MODULE,
	.open		= bcm2835_codec_open,
	.release	= bcm2835_codec_release,
	.poll		= v4l2_m2m_fop_poll,
	.unlocked_ioctl	= video_ioctl2,
	.mmap		= v4l2_m2m_fop_mmap,
};

static const struct video_device bcm2835_codec_videodev = {
	.name		= MEM2MEM_NAME,
	.vfl_dir	= VFL_DIR_M2M,
	.fops		= &bcm2835_codec_fops,
	.ioctl_ops	= &bcm2835_codec_ioctl_ops,
	.minor		= -1,
	.release	= video_device_release_empty,
};

static const struct v4l2_m2m_ops m2m_ops = {
	.device_run	= device_run,
	.job_ready	= job_ready,
	.job_abort	= job_abort,
};

static int bcm2835_codec_probe(struct platform_device *pdev)
{
	struct bcm2835_codec_dev *dev;
	struct video_device *vfd;
	struct vchiq_mmal_instance *instance = NULL;
	struct device_node *node = pdev->dev.of_node;
	int ret;


	dev = devm_kzalloc(&pdev->dev, sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->pdev = pdev;
//	spin_lock_init(&dev->irqlock);

	if (of_device_is_compatible(node, "raspberrypi,bcm2835-v4l2-decoder"))
		dev->decode = true;

	ret = v4l2_device_register(&pdev->dev, &dev->v4l2_dev);
	if (ret)
		return ret;

	atomic_set(&dev->num_inst, 0);
	mutex_init(&dev->dev_mutex);

	dev->vfd = bcm2835_codec_videodev;
	vfd = &dev->vfd;
	vfd->lock = &dev->dev_mutex;
	vfd->v4l2_dev = &dev->v4l2_dev;

	ret = video_register_device(vfd, VFL_TYPE_GRABBER, 0);
	if (ret) {
		v4l2_err(&dev->v4l2_dev, "Failed to register video device\n");
		goto unreg_dev;
	}

	video_set_drvdata(vfd, dev);
	snprintf(vfd->name, sizeof(vfd->name), "%s", bcm2835_codec_videodev.name);
	v4l2_info(&dev->v4l2_dev,
			"Device registered as /dev/video%d\n", vfd->num);

	//setup_timer(&dev->timer, device_isr, (long)dev);
	platform_set_drvdata(pdev, dev);

	dev->m2m_dev = v4l2_m2m_init(&m2m_ops);
	if (IS_ERR(dev->m2m_dev)) {
		v4l2_err(&dev->v4l2_dev, "Failed to init mem2mem device\n");
		ret = PTR_ERR(dev->m2m_dev);
		goto err_m2m;
	}

	ret = vchiq_mmal_init(&instance);
	if (ret < 0)
		goto err_m2m;
	dev->instance = instance;

	v4l2_err(&dev->v4l2_dev, "Loaded V4L2 %s codec\n",
		 dev->decode ? "decode" : "encode");
	return 0;

err_m2m:
	v4l2_m2m_release(dev->m2m_dev);
	video_unregister_device(&dev->vfd);
unreg_dev:
	v4l2_device_unregister(&dev->v4l2_dev);

	return ret;
}

static int bcm2835_codec_remove(struct platform_device *pdev)
{
	struct bcm2835_codec_dev *dev = platform_get_drvdata(pdev);

	v4l2_info(&dev->v4l2_dev, "Removing " MEM2MEM_NAME);
	v4l2_m2m_release(dev->m2m_dev);
	//del_timer_sync(&dev->timer);
	video_unregister_device(&dev->vfd);
	v4l2_device_unregister(&dev->v4l2_dev);

	return 0;
}

/*
 *   Register the driver with device tree
 */

static const struct of_device_id bcm2835_codec_of_match[] = {
	{.compatible = "raspberrypi,bcm2835-v4l2-decoder",},
	{.compatible = "raspberrypi,bcm2835-v4l2-encoder",},
	{ /* sentinel */ },
};

MODULE_DEVICE_TABLE(of, bcm2835_codec_of_match);

static struct platform_driver bcm2835_v4l2_codec_driver = {
	.probe = bcm2835_codec_probe,
	.remove = bcm2835_codec_remove,
	.driver = {
		   .name = BCM2835_V4L2_CODEC_MODULE_NAME,
		   .owner = THIS_MODULE,
		   .of_match_table = bcm2835_codec_of_match,
		   },
};

module_platform_driver(bcm2835_v4l2_codec_driver);
