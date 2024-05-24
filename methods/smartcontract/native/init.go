package native

import (
	"github.com/ontio/ontology-tool/methods/smartcontract/native/governance"
	"github.com/ontio/ontology-tool/methods/smartcontract/native/ontparams"
)

func RegisterNative() {
	governance.RegisterGovernance()
	ontparams.RegisterGlobalParam()
}
