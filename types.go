package main

type flanReport struct {
	IPS           []string             `json:"ips"`
	ListVulns     map[string]Vulns     `json:"vulnerable"`
	NotVulnerable map[string]Locations `json:"not_vulnerable"`
	StartDate     string               `json:"start_date"`
	NmapCommand   string               `json:"nmap_command"`
}

type Vulns struct {
	V        []VulnInfo       `json:"vulnerabilities"`
	Location map[string][]int `json:"locations"`
}

type VulnInfo struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Severity    float64 `json:"severity"`
	SeverityStr string  `json:"severity_str"`
	Description string  `json:"description"`
	URL         string  `json:"url"`
}

type Locations struct {
	Location map[string][]int `json:"locations"`
}
