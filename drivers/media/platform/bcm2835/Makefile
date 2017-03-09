bcm2835-v4l2-objs := bcm2835-camera.o controls.o mmal-vchiq.o

obj-$(CONFIG_VIDEO_BCM2835_MMAL) += bcm2835-v4l2.o

ccflags-$(CONFIG_VIDEO_BCM2835) += -Idrivers/staging/vc04_services -Idrivers/staging/vc04_services/interface/vcos/linuxkernel -D__VCCOREVER__=0x04000000

obj-$(CONFIG_VIDEO_BCM2835_UNICAM) += bcm2835-unicam.o

cflags-$(CONFIG_VIDEO_BCM2835_UNICAM) += -D__VCCOREVER__=0x04000000
