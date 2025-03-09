# xsghost
A tool based on a collection of go scripts
Follow me on 
[LinkedIn] (https://www.linkedin.com/in/eike-de-campos-oliveira-2643b11ba/)

# Download, Build And Install.
### WINDOWS Download
```
curl -L -o xsghost.exe "https://github.com/eikehacker1/xsghost/raw/refs/heads/main/xsghost.exe"
```
### Linux Download
```
curl -L -o  xsghost "https://github.com/eikehacker1/xsghost/raw/refs/heads/main/xsghost"
```

# How to Use 

###  Use without filter

```
./xsghost.exe testphp.vulnweb.com 
```

### Use with filter

```
./xsghost.exe  -only-poc testphp.vulnweb.com 
```
### Custom Payload
```pws
 ./xsghost.exe  -only-poc -payload "<script>alert(1)</script>" testphp.vulnweb.com
```
### -h func and other features

```
 -a    Append the value instead of replacing it
  -c int
        Set concurrency (default 50)
  -dates
        show date of fetch in the first column
  -get-versions
        list URLs for crawled versions of input URL(s)
  -headers value
        Headers
  -ignore-path
        Ignore the path when considering what constitutes a duplicate
  -no-subs
        don't include subdomains of the target domain
  -only-poc
        Show only potentially vulnerable URLs
  -payload string
        XSS payload
  -proxy string
        Send traffic to a proxy (default "0")
```
### Output
![image](https://github.com/user-attachments/assets/b02c863e-3e02-4677-a53e-23bfb8c16b64)
