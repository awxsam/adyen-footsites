package adyenFootsites
import (
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"strings"
	"time"
)

type Adyen struct {
	rsa     *adrsa
	aesKey     []byte
	aesNonce   []byte
}

type Data struct {
	Number              string `json:"number"`
	Cvc                 string `json:"cvc"`
	ExpiryMonth         string `json:"expiryMonth"`
	ExpiryYear          string `json:"expiryYear"`
	Generationtime      string `json:"generationtime"`
}


type ExpiryYear struct {
	ExpiryYear          string `json:"expiryYear"`
	Generationtime      string `json:"generationtime"`
}

type ExpiryMonth struct {
	ExpiryMonth         string `json:"expiryMonth"`
	Generationtime      string `json:"generationtime"`
}
type CVC struct {
	CVC         string `json:"cvc"`
	Generationtime      string `json:"generationtime"`
}
type CreditCardNumber struct {
	Number              string `json:"number"`
	Generationtime      string `json:"generationtime"`
}

func NewAdyen(publicKey string) *Adyen {
	y := &Adyen{}
	y.rsa = NewRsa()
	y.aesKey = make([]byte, 32)

	err := y.rsa.Init(publicKey, 65537)
	if err != nil {
		panic(err)
	}
	return y
}



func (y *Adyen) random(len int) []byte {
	ak := make([]byte, len)
	rand.Read(ak)
	return ak
}
func (y *Adyen) EncryptCreditcardDetails(CCNumber string,ExpMonth string, ExpYear string, Cvc string) (EncryptedCCNumber string, EncryptedExpMonth string, EncryptedExpYear string, EncryptedCvc string){
	EncryptedCCNumber,_ = y.EncryptCC(CCNumber,"","","")
	EncryptedExpMonth,_ = y.EncryptCC("",ExpMonth,"","")
	EncryptedExpYear,_ = y.EncryptCC("","",ExpYear,"")
	EncryptedCvc,_ = y.EncryptCC("","","",Cvc)
	return
}
func (y *Adyen) EncryptCC(CCnumber string, ExpMonth string, ExpYear string, Cvc string) (string, error) {
	y.aesKey = y.random(32)
	y.aesNonce = y.random(12)
	gt := time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	bytes,_ := json.Marshal(Data{})

	if CCnumber != ""{
		info := CreditCardNumber{
			Number:          CCnumber,
			Generationtime: gt,
		}
		bytes,_ = json.Marshal(info)
	}
	if ExpMonth != "" {
		info := ExpiryMonth{
			ExpiryMonth:          ExpMonth,
			Generationtime: gt,
		}
		bytes,_ = json.Marshal(info)
	}
	if ExpYear != ""{
		info := ExpiryYear{
			ExpiryYear:          ExpYear,
			Generationtime: gt,
		}
		bytes,_ = json.Marshal(info)
	}
	if Cvc != "" {
		info := CVC{
			CVC:          Cvc,
			Generationtime: gt,
		}
		bytes,_ = json.Marshal(info)
	}

	y.aesKey = y.random(32)
	y.aesNonce = y.random(12)
	block, err := aes.NewCipher(y.aesKey)
	if err != nil {
		return "", err
	}
	cmer, err := NewCCM(block, 8, len(y.aesNonce))
	if err != nil {
		return "", err
	}

	cipherBytes := cmer.Seal(nil, y.aesNonce, bytes, nil)
	cipherBytes = append(y.aesNonce, cipherBytes...)
	cipherText := base64.StdEncoding.EncodeToString(cipherBytes)

	encryptedPublicKey, err := y.rsa.encryptWithAesKey(y.aesKey)
	if err != nil {
		return "", err
	}
	prefix := "adyenjs_0_1_18$"
	arr := []string{prefix, encryptedPublicKey, "$", cipherText}
	return strings.Join(arr, ""), nil
}
