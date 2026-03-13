obj-m += file_copy.o


ifneq ($(KDIR),)
$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))
endif

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(PWD) -C $(KDIR) M=$(PWD) clean