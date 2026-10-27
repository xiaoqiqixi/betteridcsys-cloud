module aster/cloud

go 1.26.0

require (
	aster/billing v0.0.0
	filippo.io/age v1.3.2
	github.com/go-sql-driver/mysql v1.9.3
	golang.org/x/sys v0.49.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	filippo.io/hpke v0.4.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
)

replace aster/billing => ../contracts/billing
