package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/loowtime/netrivox/pkg/models"
)

func JSON(w io.Writer, result models.ScanResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func CSV(w io.Writer, result models.ScanResult) error {
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"host_ip", "port", "protocol", "state", "service", "category", "version", "cve_count"}); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}
	for _, service := range result.Services {
		if err := writer.Write([]string{
			service.HostIP, strconv.Itoa(service.Port), service.Protocol,
			service.State, service.Name, service.Category, service.Version,
			strconv.Itoa(len(service.Vulnerabilities)),
		}); err != nil {
			return fmt.Errorf("write CSV service: %w", err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("flush CSV: %w", err)
	}
	return nil
}

func Table(w io.Writer, result models.ScanResult) error {
	fmt.Fprintf(w, "Scan: %s\nHosts: %d | Open services: %d\n\n", result.Scan.ID, len(result.Hosts), len(result.Services))
	if _, err := fmt.Fprintln(w, "HOST\tPORT\tSTATE\tSERVICE\tVERSION\tRISK\tCVEs"); err != nil {
		return err
	}
	for _, service := range result.Services {
		if service.State != "open" {
			continue
		}
		if _, err := fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%d\n", service.HostIP, service.Port, service.State, service.Name, service.Version, service.RiskLevel, len(service.Vulnerabilities)); err != nil {
			return err
		}
	}
	return nil
}
