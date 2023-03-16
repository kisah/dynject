SUBDIRS = injector \
		  shellcode \
		  magic \
		  payload \
		  target
 
all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@
	
clean:
	rm artifacts/* build/*
	
.PHONY: all $(SUBDIRS)
