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
