// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/seclang"
	"github.com/corazawaf/coraza/v3/types"
)

// WAF instance is used to store configurations and rules
// Every web application should have a different WAF instance,
// but you can share an instance if you are ok with sharing
// configurations, rules and logging.
// Transactions and SecLang parser requires a WAF instance
// You can use as many WAF instances as you want, and they are
// concurrent safe
type WAF interface {
	// NewTransaction Creates a new initialized transaction for this WAF instance
	NewTransaction() types.Transaction
	NewTransactionWithID(id string) types.Transaction
}

// NewWAF creates a new WAF instance with the provided configuration.
func NewWAF(config WAFConfig) (WAF, error) {
fmt.Println ("waf.go: NewWAF: 001")
	c := config.(*wafConfig)

fmt.Println ("waf.go: NewWAF: 002")
	waf := corazawaf.NewWAF()

fmt.Println ("waf.go: NewWAF: 003")
	if c.debugLogger != nil {
		waf.Logger = c.debugLogger
	}

fmt.Println ("waf.go: NewWAF: 004")
	parser := seclang.NewParser(waf)

fmt.Println ("waf.go: NewWAF: 005")
	if c.fsRoot != nil {
		parser.SetRoot(c.fsRoot)
	}

fmt.Println ("waf.go: NewWAF: 006")
	for _, r := range c.rules {
fmt.Println ("waf.go: NewWAF: 007.01")
		switch {
		case r.rule != nil:
fmt.Println ("waf.go: NewWAF: 007.02")
			if err := waf.Rules.Add(r.rule); err != nil {
				return nil, fmt.Errorf("invalid WAF config from rule: %w", err)
			}
		case r.str != "":
fmt.Println ("waf.go: NewWAF: 007.03")
			if err := parser.FromString(r.str); err != nil {
				return nil, fmt.Errorf("invalid WAF config from string: %w", err)
			}
		case r.file != "":
fmt.Println ("waf.go: NewWAF: 007.04")
			if err := parser.FromFile(r.file); err != nil {
				return nil, fmt.Errorf("invalid WAF config from file: %w", err)
			}
		}
fmt.Println ("waf.go: NewWAF: 007.END LOOP")
	}

fmt.Println ("waf.go: NewWAF: 008")
	populateAuditLog(waf, c)

fmt.Println ("waf.go: NewWAF: 009")
	if err := waf.InitAuditLogWriter(); err != nil {
fmt.Println ("waf.go: NewWAF: 010")
		return nil, fmt.Errorf("invalid WAF config from audit log: %w", err)
	}

fmt.Println ("waf.go: NewWAF: 011")
	if c.requestBodyAccess {
fmt.Println ("waf.go: NewWAF: 012")
		waf.RequestBodyAccess = true
	}

fmt.Println ("waf.go: NewWAF: 013")
	if c.requestBodyLimit != nil {
fmt.Println ("waf.go: NewWAF: 014")
		waf.RequestBodyLimit = int64(*c.requestBodyLimit)
	}

fmt.Println ("waf.go: NewWAF: 015")
	if c.requestBodyInMemoryLimit != nil {
fmt.Println ("waf.go: NewWAF: 016")
		waf.SetRequestBodyInMemoryLimit(int64(*c.requestBodyInMemoryLimit))
	}

fmt.Println ("waf.go: NewWAF: 017")
	if c.responseBodyAccess {
fmt.Println ("waf.go: NewWAF: 018")
		waf.ResponseBodyAccess = true
	}

fmt.Println ("waf.go: NewWAF: 019")
	if c.responseBodyLimit != nil {
fmt.Println ("waf.go: NewWAF: 020")
		waf.ResponseBodyLimit = int64(*c.responseBodyLimit)
	}

fmt.Println ("waf.go: NewWAF: 021")
	if c.responseBodyMimeTypes != nil {
fmt.Println ("waf.go: NewWAF: 022")
		waf.ResponseBodyMimeTypes = c.responseBodyMimeTypes
	}

fmt.Println ("waf.go: NewWAF: 023")
	if c.errorCallback != nil {
fmt.Println ("waf.go: NewWAF: 024")
		waf.ErrorLogCb = c.errorCallback
	}

fmt.Println ("waf.go: NewWAF: 025")
	if err := waf.Validate(); err != nil {
fmt.Println ("waf.go: NewWAF: 026")
		return nil, err
	}

fmt.Println ("waf.go: NewWAF: OUT")
	return wafWrapper{waf: waf}, nil
}

func populateAuditLog(waf *corazawaf.WAF, c *wafConfig) {
	if c.auditLog == nil {
		return
	}

	if c.auditLog.relevantOnly {
		waf.AuditEngine = types.AuditEngineRelevantOnly
	} else {
		waf.AuditEngine = types.AuditEngineOn
	}

	if len(c.auditLog.parts) > 0 {
		waf.AuditLogParts = c.auditLog.parts
	}

	if c.auditLog.writer != nil {
		waf.SetAuditLogWriter(c.auditLog.writer)
	}
}

type wafWrapper struct {
	waf *corazawaf.WAF
}

// NewTransaction implements the same method on WAF.
func (w wafWrapper) NewTransaction() types.Transaction {
	return w.waf.NewTransaction()
}

// NewTransactionWithID implements the same method on WAF.
func (w wafWrapper) NewTransactionWithID(id string) types.Transaction {
	return w.waf.NewTransactionWithID(id)
}
