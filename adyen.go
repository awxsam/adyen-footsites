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
	rsa      *adrsa
	aesKey   []byte
	aesNonce []byte
}

type Data struct {
	Number         string `json:"number"`
	Cvc            string `json:"cvc"`
	ExpiryMonth    string `json:"expiryMonth"`
	ExpiryYear     string `json:"expiryYear"`
	Generationtime string `json:"generationtime"`
	TEST           string `json:"t"`
}

type ExpiryYear struct {
	ExpiryYear      string `json:"expiryYear"`
	Generationtime  string `json:"generationtime"`
	InitializeCount string `json:"initializeCount"`
	Activate        string `json:"activate"`
	Deactivate      string `json:"deactivate"`
	DfValue         string `json:"dfValue"`
}

type ExpiryMonth struct {
	ExpiryMonth     string `json:"expiryMonth"`
	Generationtime  string `json:"generationtime"`
	InitializeCount string `json:"initializeCount"`
	Activate        string `json:"activate"`
	Deactivate      string `json:"deactivate"`
	DfValue         string `json:"dfValue"`
}
type CVC struct {
	CVC             string `json:"cvc"`
	Generationtime  string `json:"generationtime"`
	InitializeCount string `json:"initializeCount"`
	Activate        string `json:"activate"`
	Deactivate      string `json:"deactivate"`
	DfValue         string `json:"dfValue"`
}
type CreditCardNumber struct {
	Number              string `json:"number"`
	Generationtime      string `json:"generationtime"`
	InitializeCount     string `json:"initializeCount"`
	Activate            string `json:"activate"`
	Deactivate          string `json:"deactivate"`
	DfValue             string `json:"dfValue"`
	LuhnFailCount       string `json:"luhnFailCount"`
	LuhnSameLengthCount string `json:"luhnSameLengthCount"`
	LuhnCount           string `json:"luhnCount"`
	LuhnOkCount         string `json:"luhnOkCount"`
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
func (y *Adyen) EncryptCreditcardDetails(CCNumber string, ExpMonth string, ExpYear string, Cvc string) (EncryptedCCNumber string, EncryptedExpMonth string, EncryptedExpYear string, EncryptedCvc string, err error) {
	EncryptedCCNumber, err = y.EncryptCC(CCNumber, "", "", "")
	if err != nil {
		return "", "", "", "", err
	}
	EncryptedExpMonth, err = y.EncryptCC("", ExpMonth, "", "")
	if err != nil {
		return "", "", "", "", err
	}
	EncryptedExpYear, err = y.EncryptCC("", "", ExpYear, "")
	if err != nil {
		return "", "", "", "", err
	}
	EncryptedCvc, err = y.EncryptCC("", "", "", Cvc)
	if err != nil {
		return "", "", "", "", err
	}
	return
}
func (y *Adyen) EncryptCC(CCnumber string, ExpMonth string, ExpYear string, Cvc string) (string, error) {
	y.aesKey = y.random(32)
	y.aesNonce = y.random(12)
	gt := time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	bytes, _ := json.Marshal(Data{})

	if CCnumber != "" {
		info := CreditCardNumber{
			Number:              CCnumber,
			Generationtime:      gt,
			InitializeCount:     "1",
			Activate:            "3",
			Deactivate:          "2",
			DfValue:             "DpqwU4zEdN0050000000000000KZbIQj6kzs0050271576cVB94iKzBGjQFA1T5jGxBix7RX3az8002rKkEK1Ha8P00000YVxEr00000fKkhnraRhX1B2M2Y8Asg:40",
			LuhnFailCount:       "1",
			LuhnSameLengthCount: "1",
			LuhnCount:           "1",
			LuhnOkCount:         "1",
		}
		bytes, _ = json.Marshal(info)
	}
	if ExpMonth != "" {
		info := ExpiryMonth{
			ExpiryMonth:     ExpMonth,
			Generationtime:  gt,
			InitializeCount: "1",
			Activate:        "3",
			Deactivate:      "2",
			DfValue:         "DpqwU4zEdN0050000000000000KZbIQj6kzs0050271576cVB94iKzBGjQFA1T5jGxBix7RX3az8002rKkEK1Ha8P00000YVxEr00000fKkhnraRhX1B2M2Y8Asg:40",
		}
		bytes, _ = json.Marshal(info)
	}
	if ExpYear != "" {
		info := ExpiryYear{
			ExpiryYear:      ExpYear,
			Generationtime:  gt,
			InitializeCount: "1",
			Activate:        "3",
			Deactivate:      "2",
			DfValue:         "DpqwU4zEdN0050000000000000KZbIQj6kzs0050271576cVB94iKzBGjQFA1T5jGxBix7RX3az8002rKkEK1Ha8P00000YVxEr00000fKkhnraRhX1B2M2Y8Asg:40",
		}
		bytes, _ = json.Marshal(info)
	}
	if Cvc != "" {
		info := CVC{
			CVC:             Cvc,
			Generationtime:  gt,
			InitializeCount: "1",
			Activate:        "3",
			Deactivate:      "2",
			DfValue:         "DpqwU4zEdN0050000000000000KZbIQj6kzs0050271576cVB94iKzBGjQFA1T5jGxBix7RX3az8002rKkEK1Ha8P00000YVxEr00000fKkhnraRhX1B2M2Y8Asg:40",
		}
		bytes, _ = json.Marshal(info)
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
	prefix := "adyenjs_0_1_25$"
	arr := []string{prefix, encryptedPublicKey, "$", cipherText}
	return strings.Join(arr, ""), nil
}
