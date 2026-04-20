package database

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Store wraps a GORM DB connection.
type Store struct {
	db *gorm.DB
}

// NewStore opens a SQLite database at the given path and returns a Store.
func NewStore(dbPath string) (*Store, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// DB returns the underlying *gorm.DB for raw queries.
func (s *Store) DB() *gorm.DB {
	return s.db
}

// AutoMigrate creates/updates all tables from GORM models.
func (s *Store) AutoMigrate() error {
	return s.db.AutoMigrate(
		&User{},
		&Secret{},
		&Comment{},
		&ResetToken{},
		&Order{},
		&Document{},
		&Invoice{},
		&ApiToken{},
		&Notification{},
	)
}

