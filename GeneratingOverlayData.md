## Generating Overlay Data ##

If volafox can't analysis dumped memory because of overlay data error, You can create overlay data using _overlay\_generator.py_

**overlay filename format : KERNEL VERSION\_ARCHITECTURE.overlay**

```
# python overlay_generator.py 
overlay generator - n0fate(Chris Leat's Idea) 
Contact: rapfer@gmail.com or n0fate@live.com
usage: python overlay_generator.py KERNELIMAGE OVERAY [32/64]
#
```

Now let's run a _overlay\_generator.py_ for generating 32bit Mac OS X Lion(10.7.1) overlay data

```
# python overlay_generator.py mach_kernel 10.7.1_32.overlay 32
```