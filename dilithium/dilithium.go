package dilithium

import (
	"github.com/theQRL/go-qrllib-crypto/helper"
	"github.com/theQRL/qrllib/goqrllib/dilithium"
	"reflect"
	"runtime"
)

type DilithiumInterface interface {
	Sign(message []byte) []byte
}

type Dilithium struct {
	d dilithium.Dilithium
}

func (d *Dilithium) PK() []byte {
	return helper.UCharVectorToBytes(d.d.GetPK())
}

func (d *Dilithium) SK() []byte {
	return helper.UCharVectorToBytes(d.d.GetSK())
}

func (d *Dilithium) Sign(message []byte) []byte {
	msg := helper.NewUCharVector()
	msg.New(d.d.Sign(helper.BytesToUCharVector(message).GetData()))
	return msg.GetBytes()
}

func DilithiumVerify(signature []byte, pk []byte, message []byte) bool {
	u := helper.Int64ToUCharVector(int64(len(message)))
	uSignature := helper.BytesToUCharVector(signature)
	uPK := helper.BytesToUCharVector(pk)
	dilithium.DilithiumSign_open(u.GetData(), uSignature.GetData(), uPK.GetData())

	bytesData := helper.UCharVectorToBytes(dilithium.DilithiumExtract_message(u.GetData()))
	return reflect.DeepEqual(bytesData, message)
}

func RecoverDilithium(pk []byte, sk []byte) *Dilithium {
	d := dilithium.NewDilithium__SWIG_1(helper.BytesToUCharVector(pk).GetData(),
		helper.BytesToUCharVector(sk).GetData())
	dilith := &Dilithium{d}

	// Finalizer to clean up memory allocated by C++ when object becomes unreachable
	runtime.SetFinalizer(dilith,
		func(d *Dilithium) {
			dilithium.DeleteDilithium(d.d)
		})
	return dilith
}

func NewDilithium() *Dilithium {
	d := dilithium.NewDilithium__SWIG_0()
	dilith := &Dilithium{d}

	// Finalizer to clean up memory allocated by C++ when object becomes unreachable
	runtime.SetFinalizer(dilith,
		func(d *Dilithium) {
			dilithium.DeleteDilithium(d.d)
		})
	return dilith
}
