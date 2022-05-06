package state

import (
	"bytes"
	"fmt"
	"github.com/0xPolygon/polygon-edge/chain"
	"github.com/0xPolygon/polygon-edge/state/runtime"
	"github.com/0xPolygon/polygon-edge/state/runtime/evm"
	"math"
	"math/big"

	iradix "github.com/hashicorp/go-immutable-radix"
	"github.com/umbracle/fastrlp"

	"github.com/0xPolygon/polygon-edge/crypto"
	"github.com/0xPolygon/polygon-edge/types"
)

type State interface {
	NewSnapshotAt(types.Hash) (Snapshot, error)
	NewSnapshot() Snapshot
	GetCode(hash types.Hash) ([]byte, bool)
}

type Snapshot interface {
	Get(k []byte) ([]byte, bool)
	Commit(objs []*Object) (Snapshot, []byte)
}

// account trie
type accountTrie interface {
	Get(k []byte) ([]byte, bool)
}

// Account is the account reference in the ethereum state
type Account struct {
	Nonce    uint64
	Balance  *big.Int
	Root     types.Hash
	CodeHash []byte
	Trie     accountTrie
}

func (a *Account) MarshalWith(ar *fastrlp.Arena) *fastrlp.Value {
	v := ar.NewArray()
	v.Set(ar.NewUint(a.Nonce))
	v.Set(ar.NewBigInt(a.Balance))
	v.Set(ar.NewBytes(a.Root.Bytes()))
	v.Set(ar.NewBytes(a.CodeHash))

	return v
}

var accountParserPool fastrlp.ParserPool

func (a *Account) UnmarshalRlp(b []byte) error {
	p := accountParserPool.Get()
	defer accountParserPool.Put(p)

	v, err := p.Parse(b)
	if err != nil {
		return err
	}

	elems, err := v.GetElems()

	if err != nil {
		return err
	}

	if len(elems) != 4 {
		return fmt.Errorf("bad")
	}

	// nonce
	if a.Nonce, err = elems[0].GetUint64(); err != nil {
		return err
	}
	// balance
	if a.Balance == nil {
		a.Balance = new(big.Int)
	}

	if err = elems[1].GetBigInt(a.Balance); err != nil {
		return err
	}
	// root
	if err = elems[2].GetHash(a.Root[:]); err != nil {
		return err
	}
	// codeHash
	if a.CodeHash, err = elems[3].GetBytes(a.CodeHash[:0]); err != nil {
		return err
	}

	return nil
}

func (a *Account) String() string {
	return fmt.Sprintf("%d %s", a.Nonce, a.Balance.String())
}

func (a *Account) Copy() *Account {
	aa := new(Account)

	aa.Balance = big.NewInt(1).SetBytes(a.Balance.Bytes())
	aa.Nonce = a.Nonce
	aa.CodeHash = a.CodeHash
	aa.Root = a.Root
	aa.Trie = a.Trie

	return aa
}

var emptyCodeHash = crypto.Keccak256(nil)

// StateObject is the internal representation of the account
type StateObject struct {
	Account   *Account
	Code      []byte
	Suicide   bool
	Deleted   bool
	DirtyCode bool
	Txn       *iradix.Txn
}

func (s *StateObject) Empty() bool {
	return s.Account.Nonce == 0 && s.Account.Balance.Sign() == 0 && bytes.Equal(s.Account.CodeHash, emptyCodeHash)
}

var stateStateParserPool fastrlp.ParserPool

func (s *StateObject) GetCommitedState(key types.Hash) types.Hash {
	val, ok := s.Account.Trie.Get(key.Bytes())
	if !ok {
		return types.Hash{}
	}

	p := stateStateParserPool.Get()
	defer stateStateParserPool.Put(p)

	v, err := p.Parse(val)
	if err != nil {
		return types.Hash{}
	}

	res := []byte{}
	if res, err = v.GetBytes(res[:0]); err != nil {
		return types.Hash{}
	}

	return types.BytesToHash(res)
}

// Copy makes a copy of the state object
func (s *StateObject) Copy() *StateObject {
	ss := new(StateObject)

	// copy account
	ss.Account = s.Account.Copy()

	ss.Suicide = s.Suicide
	ss.Deleted = s.Deleted
	ss.DirtyCode = s.DirtyCode
	ss.Code = s.Code

	if s.Txn != nil {
		ss.Txn = s.Txn.CommitOnly().Txn()
	}

	return ss
}

// Object is the serialization of the radix object (can be merged to StateObject?).
type Object struct {
	Address  types.Address
	CodeHash types.Hash
	Balance  *big.Int
	Root     types.Hash
	Nonce    uint64
	Deleted  bool

	// TODO: Move this to executor
	DirtyCode bool
	Code      []byte

	Storage []*StorageObject
}

// StorageObject is an entry in the storage
type StorageObject struct {
	Deleted bool
	Key     []byte
	Val     []byte
}

func GenerateContractAccount(
	config chain.ForksInTime,
	state State,
	contractAddress types.Address,
	contractBytecode []byte,
) (*chain.GenesisAccount, error) {
	//	genesis account fields generated with the contract
	var (
		contractNonce   uint64
		contractCode    []byte
		contractStorage map[types.Hash]types.Hash
	)

	// create contract
	contract := runtime.NewContractCreation(
		1,
		types.ZeroAddress,
		types.ZeroAddress,
		contractAddress,
		big.NewInt(0),
		math.MaxInt64,
		contractBytecode,
	)

	// create transaction that will mutate the state trie
	txn := NewTxn(state, state.NewSnapshot())

	// create transition
	transition := &Transition{
		config: config,
		state:  txn,
		r: &Executor{
			runtimes: []runtime.Runtime{
				evm.NewEVM(),
			},
		},
	}

	// run the transition
	res := transition.run(contract, transition)
	if res.Err != nil {
		panic("bad - evm failed")
	}

	// walk the state and collect storage
	storageEntries := make(map[types.Hash]types.Hash)
	transition.state.txn.Root().Walk(func(k []byte, v interface{}) bool {
		accountAddress := types.BytesToAddress(k)
		if accountAddress != contractAddress {
			return false
		}

		obj := v.(*StateObject)
		obj.Txn.Root().Walk(func(k []byte, v interface{}) bool {
			key := types.BytesToHash(k)
			value := types.BytesToHash(v.([]byte))

			storageEntries[key] = value

			return false
		})

		return true
	})

	// create genesis account
	if config.EIP158 {
		contractNonce = 1
	}

	contractStorage = storageEntries
	contractCode = res.ReturnValue

	stakingAccount := &chain.GenesisAccount{
		Nonce:   contractNonce,
		Code:    contractCode,
		Storage: contractStorage,
	}

	return stakingAccount, nil
}
