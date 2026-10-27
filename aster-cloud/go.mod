module aster/cloud

go 1.26.0

require (
	aster/billing v0.0.0
	github.com/go-sql-driver/mysql v1.9.3
)

require filippo.io/edwards25519 v1.1.1 // indirect

replace aster/billing => ../contracts/billing
