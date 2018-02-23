# SPDX-License-Identifier: GPL-2.0
bcm2835-codec-objs := bcm2835-v4l2-codec.o mmal-vchiq.o

obj-$(CONFIG_VIDEO_DECODE_BCM2835) += bcm2835-codec.o

ccflags-y += \
	-Idrivers/staging/vc04_services \
	-D__VCCOREVER__=0x04000000
