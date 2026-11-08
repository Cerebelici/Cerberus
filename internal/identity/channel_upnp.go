package identity

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// UPnPIdentity contains device attributes extracted via HTTP / UPnP interrogation.
type UPnPIdentity struct {
	FriendlyName string
	Manufacturer string
	ModelName    string
	ModelNumber  string
	DeviceType   string
	HTMLTitle    string
}

// QueryUPnPEndpoint probes target IP and ports for UPnP XML descriptors and HTTP titles.
func QueryUPnPEndpoint(ctx context.Context, ip string, candidatePorts []int, timeout time.Duration) (*UPnPIdentity, error) {
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	if len(candidatePorts) == 0 {
		candidatePorts = []int{80, 8080, 5000, 8008, 8009, 49152, 49153}
	}

	client := &http.Client{
		Timeout: timeout,
	}

	id := &UPnPIdentity{}

	for _, port := range candidatePorts {
		select {
		case <-ctx.Done():
			return id, ctx.Err()
		default:
		}

		// Try UPnP XML paths first
		xmlUrls := []string{
			fmt.Sprintf("http://%s:%d/description.xml", ip, port),
			fmt.Sprintf("http://%s:%d/rootDesc.xml", ip, port),
			fmt.Sprintf("http://%s:%d/ssdp/device-desc.xml", ip, port),
			fmt.Sprintf("http://%s:%d/setup.xml", ip, port),
		}

		for _, u := range xmlUrls {
			req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == 200 {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
				_ = resp.Body.Close()
				content := string(body)

				fn := extractXMLTag(content, "friendlyName")
				mfg := extractXMLTag(content, "manufacturer")
				model := extractXMLTag(content, "modelName")
				num := extractXMLTag(content, "modelNumber")
				dt := extractXMLTag(content, "deviceType")

				if fn != "" || mfg != "" || model != "" {
					id.FriendlyName = fn
					id.Manufacturer = mfg
					id.ModelName = model
					id.ModelNumber = num
					id.DeviceType = dt
					return id, nil
				}
			} else if resp != nil {
				_ = resp.Body.Close()
			}
		}

		// If no UPnP XML, try reading root HTML title
		rootUrl := fmt.Sprintf("http://%s:%d/", ip, port)
		req, err := http.NewRequestWithContext(ctx, "GET", rootUrl, nil)
		if err == nil {
			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == 200 {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
				_ = resp.Body.Close()
				title := extractHTMLTitle(string(body))
				if title != "" && id.HTMLTitle == "" {
					id.HTMLTitle = title
				}
			} else if resp != nil {
				_ = resp.Body.Close()
			}
		}
	}

	return id, nil
}

func extractHTMLTitle(html string) string {
	lower := strings.ToLower(html)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += len("<title>")
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	title := strings.TrimSpace(html[start : start+end])
	// Filter common useless titles
	if strings.Contains(strings.ToLower(title), "404") || strings.Contains(strings.ToLower(title), "not found") {
		return ""
	}
	return title
}
