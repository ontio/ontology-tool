/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

package ontparams

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"time"

	log4 "github.com/alecthomas/log4go"
	"github.com/ontio/ontology-crypto/keypair"
	sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology-tool/common"
	"github.com/ontio/ontology-tool/config"
	"github.com/ontio/ontology-tool/methods/smartcontract/native/governance"
	ocommon "github.com/ontio/ontology/common"

	"github.com/ontio/ontology/smartcontract/service/native/global_params"
	ontutils "github.com/ontio/ontology/smartcontract/service/native/utils"
)

type TransferAdminParam struct {
	CurrentAdminAccountFiles   []string `json:"CurrentAdminAccountFiles"`
	CurrentAdminAccountPubKeys []string `json:"CurrentAdminAccountPubKeys"`
	Admin                      string   `json:"Admin"`
}

func TransferGlobalParamAdmin(ontSdk *sdk.OntologySdk) bool {
	data, err := ioutil.ReadFile("./params/TransferOntParamAdmin.json")
	if err != nil {
		log4.Error("ioutil.ReadFile failed ", err)
		return false
	}
	var input TransferAdminParam
	err = json.Unmarshal(data, &input)
	if err != nil {
		log4.Error("json.Unmarshal failed ", err)
		return false
	}
	b, _ := json.MarshalIndent(input, "", "  ")
	log4.Debug("input: %s", string(b))

	var (
		users   []*sdk.Account
		pubKeys []keypair.PublicKey
	)

	time.Sleep(1 * time.Second)
	for _, path := range input.CurrentAdminAccountFiles {
		user, ok := common.GetAccountByPassword(ontSdk, path)
		if !ok {
			log4.Debug("get password for path: %s fail", path)
			return false
		}
		users = append(users, user)
	}

	for _, v := range input.CurrentAdminAccountPubKeys {
		vByte, err := hex.DecodeString(v)
		if err != nil {
			log4.Error("hex.DecodeString failed ", err)
			return false
		}
		k, err := keypair.DeserializePublicKey(vByte)
		if err != nil {
			log4.Error("keypair.DeserializePublicKey failed ", err)
			return false
		}
		pubKeys = append(pubKeys, k)
	}
	newAdmin, err := ocommon.AddressFromBase58(input.Admin)
	if err != nil {
		log4.Debug("can not get new admin address", newAdmin)
		return false
	}

	txHash, err := common.InvokeNativeContractWithMultiSign(ontSdk, config.DefConfig.GasPrice, config.DefConfig.GasLimit, pubKeys, users, governance.OntIDVersion, ontutils.ParamContractAddress, global_params.TRANSFER_ADMIN_NAME, []interface{}{newAdmin})
	if err != nil {
		log4.Error("invokeNativeContract error :", err)
		return false
	}
	log4.Info("TransferOntParamAdmin txHash is :", txHash.ToHexString())
	return true
}

type AcceptAdminParam struct {
	AcceptAdminAccountFiles   []string `json:"AcceptAdminAccountFiles"`
	AcceptAdminAccountPubKeys []string `json:"AcceptAdminAccountPubKeys"`
	Admin                     string   `json:"Admin"`
}

func AcceptGlobalParamAdmin(ontSdk *sdk.OntologySdk) bool {
	data, err := ioutil.ReadFile("./params/AcceptOntParamAdmin.json")
	if err != nil {
		log4.Error("ioutil.ReadFile failed ", err)
		return false
	}
	var input AcceptAdminParam
	err = json.Unmarshal(data, &input)
	if err != nil {
		log4.Error("json.Unmarshal failed ", err)
		return false
	}
	b, _ := json.MarshalIndent(input, "", "  ")
	log4.Debug("input: %s", string(b))

	var (
		users   []*sdk.Account
		pubKeys []keypair.PublicKey
	)

	time.Sleep(1 * time.Second)
	for _, path := range input.AcceptAdminAccountFiles {
		user, ok := common.GetAccountByPassword(ontSdk, path)
		if !ok {
			log4.Debug("get password for path: %s fail", path)
			return false
		}
		users = append(users, user)
	}

	for _, v := range input.AcceptAdminAccountPubKeys {
		vByte, err := hex.DecodeString(v)
		if err != nil {
			log4.Error("hex.DecodeString failed ", err)
			return false
		}
		k, err := keypair.DeserializePublicKey(vByte)
		if err != nil {
			log4.Error("keypair.DeserializePublicKey failed ", err)
			return false
		}
		pubKeys = append(pubKeys, k)
	}

	newAdmin, err := ocommon.AddressFromBase58(input.Admin)
	if err != nil {
		log4.Debug("can not get new admin address", newAdmin)
		return false
	}

	txHash, err := common.InvokeNativeContractWithMultiSign(ontSdk, config.DefConfig.GasPrice, config.DefConfig.GasLimit, pubKeys, users, governance.OntIDVersion, ontutils.ParamContractAddress, global_params.ACCEPT_ADMIN_NAME, []interface{}{newAdmin})
	if err != nil {
		log4.Error("invokeNativeContract error :", err)
		return false
	}
	log4.Info("AcceptOntParamAdmin txHash is :", txHash.ToHexString())
	return true
}

type SetOperatorParam struct {
	AcceptAdminAccountFiles   []string `json:"AcceptAdminAccountFiles"`
	AcceptAdminAccountPubKeys []string `json:"AcceptAdminAccountPubKeys"`
	Operator                  string   `json:"Operator"`
}

func SetOntParamOperator(ontSdk *sdk.OntologySdk) bool {
	data, err := ioutil.ReadFile("./params/SetOntParamOperator.json")
	if err != nil {
		log4.Error("ioutil.ReadFile failed ", err)
		return false
	}
	var input SetOperatorParam
	err = json.Unmarshal(data, &input)
	if err != nil {
		log4.Error("json.Unmarshal failed ", err)
		return false
	}
	b, _ := json.MarshalIndent(input, "", "  ")
	log4.Debug("input: %s", string(b))

	var (
		users   []*sdk.Account
		pubKeys []keypair.PublicKey
	)

	time.Sleep(1 * time.Second)
	for _, path := range input.AcceptAdminAccountFiles {
		user, ok := common.GetAccountByPassword(ontSdk, path)
		if !ok {
			log4.Debug("get password for path: %s fail", path)
			return false
		}
		users = append(users, user)
	}

	for _, v := range input.AcceptAdminAccountPubKeys {
		vByte, err := hex.DecodeString(v)
		if err != nil {
			log4.Error("hex.DecodeString failed ", err)
			return false
		}
		k, err := keypair.DeserializePublicKey(vByte)
		if err != nil {
			log4.Error("keypair.DeserializePublicKey failed ", err)
			return false
		}
		pubKeys = append(pubKeys, k)
	}

	newop, err := ocommon.AddressFromBase58(input.Operator)
	if err != nil {
		log4.Debug("can not get new admin address", err)
		return false
	}

	txHash, err := common.InvokeNativeContractWithMultiSign(ontSdk, config.DefConfig.GasPrice, config.DefConfig.GasLimit, pubKeys, users, governance.OntIDVersion, ontutils.ParamContractAddress, global_params.SET_OPERATOR, []interface{}{newop})
	if err != nil {
		log4.Error("invokeNativeContract error :", err)
		return false
	}

	log4.Info("SetOntParamOperator txHash is :", txHash.ToHexString())
	return true
}
