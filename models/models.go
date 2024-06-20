// models.go
package models

import (
	"time"
)

type RequestHeader struct {
    ID          string    `gorm:"primaryKey"`
    TimeStamp   time.Time
    ClientName  string
    UserID      string
}

type RequestBody struct {
    ID                  uint   `gorm:"primaryKey"`
    EncryptedCryptoKey  string
    EncryptedCryptoIV   string
    Payload             string
    Signature           string
    RequestHeaderID     string
    RequestHeader       RequestHeader `gorm:"foreignKey:RequestHeaderID"`
}

type IRequest struct {
    ID     uint        `gorm:"primaryKey"`
    Header RequestHeader
    Body   RequestBody
}
