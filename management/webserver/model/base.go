package model

import (
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/management/webserver/pkg/log"
)

// Base is a replacement for gorm.Model without DeletedAt, which is considered to be not good.
type Base struct {
	ID        uint      `gorm:"primarykey"  json:"id"`
	CreatedAt time.Time `                   json:"created_at"`
	UpdatedAt time.Time `                   json:"updated_at"`
}

var logger = log.GetLogger("model")
