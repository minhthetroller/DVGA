// Package database provides GORM models and the data-access layer for DVGA.
package database

import "time"

// User is the GORM model for the users table.
type User struct {
	ID             uint   `gorm:"primaryKey"`
	Username       string `gorm:"uniqueIndex;not null"`
	Password       string `gorm:"not null"`
	Role           string `gorm:"not null;default:user"`
	SecretQuestion string
	SecretAnswer   string
	Email          string
	Phone          string
}

// Secret is the GORM model for the secrets table.
type Secret struct {
	ID     uint   `gorm:"primaryKey"`
	UserID uint   `gorm:"not null;index"`
	Title  string `gorm:"not null"`
	Value  string `gorm:"not null"`
}

// Comment is the GORM model for the guestbook comments table (XSS Stored).
type Comment struct {
	ID        uint   `gorm:"primaryKey"`
	Username  string `gorm:"not null"`
	Body      string `gorm:"not null"`
	CreatedAt time.Time
}

// ResetToken is the GORM model for password reset tokens (Insecure Design).
type ResetToken struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint `gorm:"not null;index"`
	Token     string
	CreatedAt time.Time
	Used      bool `gorm:"default:false"`
}

// Order is the GORM model for customer orders (BOLA, BOPLA, BFLA).
type Order struct {
	ID             uint      `gorm:"primaryKey"`
	UserID         uint      `gorm:"not null;index"`
	Product        string    `gorm:"not null"`
	Amount         float64   `gorm:"not null"`
	Status         string    `gorm:"not null;default:pending"` // pending / shipped / cancelled / refunded
	TrackingNumber string
	CardLast4      string
	CVV            string
	AssignedTo     uint      `gorm:"default:0"` // helpdesk user assigned to this order
	CreatedAt      time.Time
}

// Document is the GORM model for shared documents (BOLA).
type Document struct {
	ID             uint   `gorm:"primaryKey"`
	OwnerUserID    uint   `gorm:"not null;index"`
	Title          string `gorm:"not null"`
	Body           string `gorm:"not null"`
	Classification string `gorm:"not null;default:internal"` // public / internal / confidential
}

// Invoice is the GORM model for invoices (BOPLA).
type Invoice struct {
	ID      uint    `gorm:"primaryKey"`
	UserID  uint    `gorm:"not null;index"`
	OrderID uint    `gorm:"not null;index"`
	Amount  float64 `gorm:"not null"`
	Status  string  `gorm:"not null;default:open"` // open / paid / voided
	Notes   string
}

// APIToken is the GORM model for API tokens (Broken Auth).
type APIToken struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    uint      `gorm:"not null;index"`
	Token     string    `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time
	Revoked   bool `gorm:"default:false"`
}

// Notification is the GORM model for notifications (Unrestricted Resource).
type Notification struct {
	ID        uint      `gorm:"primaryKey"`
	SenderID  uint      `gorm:"not null;index"`
	Recipient string    `gorm:"not null"`
	Body      string    `gorm:"not null"`
	CreatedAt time.Time
}

