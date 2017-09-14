
#include <linux/i2c.h>
#include <linux/slab.h>
#include <linux/videodev2.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <asm/div64.h>
#include <media/v4l2-device.h>
#include <media/v4l2-ctrls.h>
#include <media/i2c/mt9v011.h>

struct ev76c560 {
	struct v4l2_subdev sd;
	#ifdef CONFIG_MEDIA_CONTROLLER
		struct media_pad pad;
	#endif
	struct v4l2_ctrl_handler ctrls;
	unsigned width, height;
	unsigned xtal;
	unsigned hflip:1;
	unsigned vflip:1;

	u16 global_gain, exposure;
	s16 red_bal, blue_bal;
};

static inline struct ev76c560 *to_ev76c560(struct v4l2_subdev *sd)
{
	return container_of(sd, struct ev76c560, sd);
}


static int ev76c560_read(struct v4l2_subdev *sd, unsigned char addr)
{
	struct i2c_client *c = v4l2_get_subdevdata(sd);
	__be16 buffer;
	int rc, val;

	rc = i2c_master_send(c, &addr, 1);
	//if (rc != 1)
	// v4l2_dbg(0, debug, sd,
	// "i2c i/o error: rc == %d (should be 1)\n", rc);

	msleep(10);

	rc = i2c_master_recv(c, (char *)&buffer, 2);
	// if (rc != 2)
	// v4l2_dbg(0, debug, sd,
	// "i2c i/o error: rc == %d (should be 2)\n", rc);

	val = be16_to_cpu(buffer);

	// v4l2_dbg(2, debug, sd, "mt9v011: read 0x%02x = 0x%04x\n", addr, val);

	return val;
}

static void ev76c560_write(struct v4l2_subdev *sd, unsigned char addr, u16 value)
{
	struct i2c_client *c = v4l2_get_subdevdata(sd);
	unsigned char buffer[3];
	int rc;

	buffer[0] = addr;
	buffer[1] = value >> 8;
	buffer[2] = value & 0xff;

	// v4l2_dbg(2, debug, sd,
	// "mt9v011: writing 0x%02x 0x%04x\n", buffer[0], value);
	rc = i2c_master_send(c, buffer, 3);
	// if (rc != 3)
	// v4l2_dbg(0, debug, sd,
	// "i2c i/o error: rc == %d (should be 3)\n", rc);
}



static int ev76c560_set_fmt(struct v4l2_subdev *sd,
	struct v4l2_subdev_pad_config *cfg,
	struct v4l2_subdev_format *format)
{
	//struct v4l2_mbus_framefmt *fmt = &format->format;
	//struct 76c560 *core = to_76c560(sd);

	/*if (format->pad || fmt->code != MEDIA_BUS_FMT_SGRBG8_1X8)
		return -EINVAL;

	v4l_bound_align_image(&fmt->width, 48, 639, 1,
	&fmt->height, 32, 480, 1, 0);
	fmt->field = V4L2_FIELD_NONE;
	fmt->colorspace = V4L2_COLORSPACE_SRGB;

	if (format->which == V4L2_SUBDEV_FORMAT_ACTIVE) {
		core->width = fmt->width;
		core->height = fmt->height;

		set_res(sd);
	} else {
		cfg->try_fmt = *fmt;
	}*/

	return 0;
}



static int ev76c560_enum_mbus_code(struct v4l2_subdev *sd,
	struct v4l2_subdev_pad_config *cfg,
	struct v4l2_subdev_mbus_code_enum *code)
{
	//if (code->pad || code->index > 0)
	// return -EINVAL;
	//
	// code->code = MEDIA_BUS_FMT_SGRBG8_1X8;
	return 0;
}



static int ev76c560_s_parm(struct v4l2_subdev *sd, struct v4l2_streamparm *parms)
{
	struct v4l2_captureparm *cp = &parms->parm.capture;
	struct v4l2_fract *tpf = &cp->timeperframe;
	u16 speed;

	if (parms->type != V4L2_BUF_TYPE_VIDEO_CAPTURE)
	return -EINVAL;
	if (cp->extendedmode != 0)
	return -EINVAL;

	// speed = calc_speed(sd, tpf->numerator, tpf->denominator);

	// mt9v011_write(sd, R0A_MT9V011_CLK_SPEED, speed);
	// v4l2_dbg(1, debug, sd, "Setting speed to %d\n", speed);

	/* Recalculate and update fps info */
	// calc_fps(sd, &tpf->numerator, &tpf->denominator);

	return 0;
}


static int ev76c560_g_parm(struct v4l2_subdev *sd, struct v4l2_streamparm *parms)
{
	struct v4l2_captureparm *cp = &parms->parm.capture;

	if (parms->type != V4L2_BUF_TYPE_VIDEO_CAPTURE)
	return -EINVAL;

	memset(cp, 0, sizeof(struct v4l2_captureparm));
	cp->capability = V4L2_CAP_TIMEPERFRAME;
	// calc_fps(sd,
	// &cp->timeperframe.numerator,
	// &cp->timeperframe.denominator);

	return 0;
}

static int ev76c560_reset(struct v4l2_subdev *sd, u32 val)
{
	// int i;

	// for (i = 0; i < ARRAY_SIZE(mt9v011_init_default); i++)
	// mt9v011_write(sd, mt9v011_init_default.reg,
	// mt9v011_init_default.value);

	// set_balance(sd);
	// set_res(sd);
	// set_read_mode(sd);

	return 0;
}

static const struct v4l2_subdev_core_ops ev76c560_core_ops = {
	.reset = ev76c560_reset,
	#ifdef CONFIG_VIDEO_ADV_DEBUG
	.g_register = mt9v011_g_register,
	.s_register = mt9v011_s_register,
	#endif
};

static const struct v4l2_subdev_video_ops ev76c560_video_ops = {
	.g_parm = ev76c560_g_parm,
	.s_parm = ev76c560_s_parm,
};

static const struct v4l2_subdev_pad_ops ev76c560_pad_ops = {
	.enum_mbus_code = ev76c560_enum_mbus_code,
	.set_fmt = ev76c560_set_fmt,
};




static const struct v4l2_subdev_ops ev76c560_ops = {
	.core = &ev76c560_core_ops,
	.video = &ev76c560_video_ops,
	.pad = &ev76c560_pad_ops,
};





static int ev76c560_probe(struct i2c_client *c,
	const struct i2c_device_id *id)
{
	printk("ev76c560 probe is by tangyuan===============================================\n");
	struct ev76c560 *core;
	struct v4l2_subdev *sd;


	if (!i2c_check_functionality(c->adapter,
			I2C_FUNC_SMBUS_READ_BYTE | I2C_FUNC_SMBUS_WRITE_BYTE_DATA))
		return -EIO;

	core = devm_kzalloc(&c->dev, sizeof(struct ev76c560), GFP_KERNEL);
	if (!core)
		return -ENOMEM;

	sd = &core->sd;
	v4l2_i2c_subdev_init(sd, c, &ev76c560_ops);
	return 0;
}

static int ev76c560_remove(struct i2c_client *c)
{
	struct v4l2_subdev *sd = i2c_get_clientdata(c);
	struct ev76c560 *core = to_ev76c560(sd);

	// v4l2_dbg(1, debug, sd,
	// "mt9v011.c: removing mt9v011 adapter on address 0x%x\n",
	// c->addr << 1);

	v4l2_device_unregister_subdev(sd);
	//v4l2_ctrl_handler_free(&core->ctrls);

	return 0;
}

#if IS_ENABLED(CONFIG_OF)
static const struct of_device_id ev76c50_of_match[] = {
	{ .compatible = "micron,ev76c50" },
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, ev76c50_of_match);
#endif

static const struct i2c_device_id ev76c560_id[] = {
	{ "ev76c560", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, ev76c560_id);

static struct i2c_driver ev76c560_driver = {
	.driver = {
	.name = "ev76c560",
	},
	.probe = ev76c560_probe,
	.remove = ev76c560_remove,
	.id_table = ev76c560_id,
};

module_i2c_driver(ev76c560_driver);
MODULE_DESCRIPTION("Micron 76c560 sensor driver");
MODULE_AUTHOR("tangyuan");
MODULE_LICENSE("GPL");
