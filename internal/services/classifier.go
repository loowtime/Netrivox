package services

import "fmt"

type Definition struct {
	Name        string
	Category    string
	Description string
}

var catalog = map[int]Definition{
	21:   {Name: "ftp", Category: "file-transfer", Description: "File Transfer Protocol"},
	22:   {Name: "ssh", Category: "remote-access", Description: "Secure Shell"},
	25:   {Name: "smtp", Category: "mail", Description: "Simple Mail Transfer Protocol"},
	53:   {Name: "dns", Category: "infrastructure", Description: "Domain Name System"},
	80:   {Name: "http", Category: "web", Description: "Hypertext Transfer Protocol"},
	110:  {Name: "pop3", Category: "mail", Description: "Post Office Protocol"},
	143:  {Name: "imap", Category: "mail", Description: "Internet Message Access Protocol"},
	443:  {Name: "https", Category: "web", Description: "HTTP over TLS"},
	445:  {Name: "smb", Category: "file-sharing", Description: "Server Message Block"},
	3306: {Name: "mysql", Category: "database", Description: "MySQL database protocol"},
	5432: {Name: "postgresql", Category: "database", Description: "PostgreSQL database protocol"},
	6379: {Name: "redis", Category: "database", Description: "Redis data store protocol"},
	8080: {Name: "http-alt", Category: "web", Description: "Alternative HTTP service"},
}

func Lookup(port int) Definition {
	if definition, ok := catalog[port]; ok {
		return definition
	}
	return Definition{
		Name:        "unknown",
		Category:    "unknown",
		Description: fmt.Sprintf("Unknown TCP service on port %d", port),
	}
}
