import fileinput
import Image, ImageDraw, ImageFont, ImageOps


# Pagesize
psize = 4096

# A column is 32MB
p_per_col = 32*1024*1024/psize
# 4 GB address space.
slots = 2*1024*1024*1024/psize/p_per_col

slotwidth = 60
pheight = 1

# colors:

size = p_per_col * pheight, slotwidth * slots

im = Image.new ("RGB", size)

draw = ImageDraw.Draw(im)
draw.rectangle ((0,0) + im.size, fill="#ffffff")


def getcolor (state, prot, prot_, type):
    if state == "free":
        return "#cccccc"
    if state == "reserve":
        if type == "image":
            return "#88ff88"
        if type == "private":
            return "#ff8888"
        if type == "mapped":
            return "#8888ff"
        return "#ffff00"
    if state == "commit":
        if type == "image":
            return "#44dd44"
        if type == "private":
            return "#dd4444"
        if type == "mapped":
            return "#4444dd"
        return "#ffff00"
    return "#ffff00"

    # alc-base   alc-prot address    size       state    protect  type     
    # 0x00000000 --- ---  0x00001000 0x0000f000 free     --- ---  unknown  
    # 0x00010000 --- ---  0x00014000 0x0000a000 reserve  --- ---  image    
    # 0x00000000 --- ---  0x0001e000 0x017a2000 free     --- ---  unknown  
    # 0x017c0000 --- ---  0x017c0000 0x000fe000 reserve  --- ---  private  
    # 0x017c0000 --- ---  0x018be000 0x00002000 commit   rw- ---  private  
    # 0x018c0000 --- ---  0x018c0000 0x00002000 commit   rw- -n-  private  


def upperleft (col, row):
    col = slots - col - 1
    return (row * pheight, col * slotwidth)

def lowerright (col, row):
    col = slots - col - 1
    return ((row + 1) * pheight - 1, (col + 1) * slotwidth - 1)


def drawit_ (draw, pstart, pstop, state, prot, prot_, type):
    col = pstart / p_per_col
    pstart = pstart - col * p_per_col
    # inclusive now
    pstop = (pstop - col * p_per_col) - 1

    # Same col for pstop, ensured by drawit
    color = getcolor (state, prot, prot_, type)
    draw.rectangle (upperleft(col, pstop) + lowerright (col, pstart),
                    color)
   

def drawit (draw, addr, size, state, prot, prot_, type):
    if addr >= 2*1024*1024*1024:
        return
    
    end = addr + size
    while addr < end:
        next = ((addr + p_per_col) / p_per_col) * p_per_col
        if next > end:
            next = end
        drawit_ (draw, addr, next, state, prot, prot_, type)
        addr = next

for line in fileinput.input():
    if line[0] != '0':
        continue
    # alc-base   alc-prot address    size       state    protect  type     
    # 0x00000000 --- ---  0x00001000 0x0000f000 free     --- ---  unknown  
    # 0x00010000 --- ---  0x00014000 0x0000a000 reserve  --- ---  image    
    # 0x00000000 --- ---  0x0001e000 0x017a2000 free     --- ---  unknown  
    # 0x017c0000 --- ---  0x017c0000 0x000fe000 reserve  --- ---  private  
    # 0x017c0000 --- ---  0x018be000 0x00002000 commit   rw- ---  private  
    # 0x018c0000 --- ---  0x018c0000 0x00002000 commit   rw- -n-  private  

    fields = line.split()
    addr, size, state, prot, prot_, type = fields[3:]
    addr = int(addr, 16) / 4096
    size = int(size, 16) / 4096

    drawit (draw, addr, size, state, prot, prot_, type)


# Create grid.
for col in xrange(slots):
    draw.line ((0, col*slotwidth) + (im.size[0], col*slotwidth), fill="#666666")
for col in xrange(3):
    draw.rectangle ((0, (col+1)*(slots/4)*slotwidth - slotwidth/16)
                    + (im.size[0], (col+1)*(slots/4)*slotwidth + slotwidth/16), fill="#666666")
for row in xrange(31):
    draw.line (((row+1)*(p_per_col/32)*pheight, 0) + (((row+1)*(p_per_col/32))*pheight, im.size[1]), fill="#666666")

del draw

# Compose documented image.
fsize = (im.size[0] + 30 * slotwidth, im.size[1] + 6 * slotwidth)
ulpaste = (28*slotwidth, 3*slotwidth)
fim = Image.new ("RGB", fsize)
draw = ImageDraw.Draw(fim)

draw.rectangle ((0,0) + fim.size, fill="#ffffff")
draw.rectangle ((ulpaste[0]-2, ulpaste[1]-2) + (ulpaste[0] + im.size[0] + 2, ulpaste[1] + im.size[1] + 2), fill="#000000")
fim.paste (im, ulpaste)

fs = int (slotwidth * 2 / 3)
dpf = ImageFont.truetype ("datapro.ttf", int(fs * 1.5))
draw.text((slotwidth/2,slotwidth), "Virtual Memory Map of Windows CE", fill="#000000", font=dpf)

dpf = ImageFont.truetype ("datapro.ttf", fs)

def getrow(i):
    return 5 + ulpaste[1] + im.size[1] - slotwidth * (i + 1)

for i in xrange(slots):
    draw.text ((ulpaste[0] - 6 * slotwidth, getrow(i) ),
               "0x%08x" % (i * 0x02000000), fill="#444444", font=dpf)

for row in xrange(32):
    txt=Image.new("L", (600,60))
    d = ImageDraw.Draw(txt)
    d.text ((0,0), "0x%08x" % (row * 0x00100000), fill=255, font=dpf)
    del d
    rtxt = txt.rotate (17.5, expand=1)
    fim.paste (ImageOps.colorize(rtxt, "#ffffff", "#444444"),
               (ulpaste[0] + (row*(p_per_col/32)*pheight), ulpaste[1] - 4*slotwidth), rtxt)
    del txt
    del rtxt

#draw.text ((ulpaste[0] + 0x00011000 * p_per_col*pheight / (32*1024*1024), ulpaste[1] + 65*slotwidth),
#           "Code/Data", fill="#000000", font=dpf)
#draw.text ((ulpaste[0] + 0x018C0000 * p_per_col*pheight / (32*1024*1024), ulpaste[1] + 65*slotwidth),
#           "Stack/Heap", fill="#000000", font=dpf)

              
def writerow(i, str):
    draw.text ((10 * slotwidth, getrow(i) ), str, fill="#000000", font=dpf)

writerow (0, "Slot  0: Active Process")
writerow (1, "Slot  1: ROM Image")
for i in xrange (31):
    writerow (2 + i, "Slot %2i: Process %i" % (i + 2, i))
for i in xrange (26):
    writerow (33 + i, "Slot %2i: Shared Area" % (33 + i))
writerow (59, "Slot 59: Driver Stacks")
writerow (60, "Slot 60: Large DLLs")
writerow (61, "Slot 61: Large DLLs")
writerow (62, "Slot 62: Shared Heaps")
writerow (63, "Slot 63: Resource DLLs")

def writelegend(i, col, str):
    draw.rectangle ((1 * slotwidth, getrow(63-i), 2 * slotwidth - 10, getrow(63-i - 1) - 10), fill=col)
    draw.rectangle ((1 * slotwidth, getrow(63-i), 2 * slotwidth - 10, getrow(63-i - 1) - 10), outline="#444444")
    draw.text ((2 * slotwidth, getrow(63-i) ), str, fill="#000000", font=dpf)

writelegend(0, "#ffffff", "unused")
writelegend(1, getcolor("free", 0, 0, ""), "free")
writelegend(2, getcolor("reserve", 0, 0, "image"), "image")
writelegend(3, getcolor("commit", 0, 0, "image"), "... committed")
writelegend(4, getcolor("reserve", 0, 0, "private"), "private")
writelegend(5, getcolor("commit", 0, 0, "private"), "... committed")
writelegend(6, getcolor("reserve", 0, 0, "mapped"), "mapped")
writelegend(7, getcolor("commit", 0, 0, "mapped"), "... committed")

def writeextra(i, str):
    draw.text ((1 * slotwidth, getrow(63-i) ), str, fill="#000000", font=dpf)
writeextra(9, "1px = 4 KB")


del draw 
fim.save("output.png", "PNG")
