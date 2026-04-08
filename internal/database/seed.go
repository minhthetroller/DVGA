package database

import "time"

// Seed inserts test data. Safe to call multiple times — skips if users already exist.
func (s *Store) Seed() error {
	var count int64
	s.db.Model(&User{}).Count(&count)
	if count > 0 {
		return nil
	}

	users := []User{
		{ID: 1, Username: "admin", Password: "admin", Role: "admin", SecretQuestion: "What is your favourite colour?", SecretAnswer: "red"},
		{ID: 2, Username: "gordonb", Password: "abc123", Role: "user", SecretQuestion: "What is your favourite colour?", SecretAnswer: "blue"},
		{ID: 3, Username: "pablo", Password: "letmein", Role: "user", SecretQuestion: "What is your pet's name?", SecretAnswer: "buddy"},
		{ID: 4, Username: "1337", Password: "charley", Role: "user", SecretQuestion: "What is your pet's name?", SecretAnswer: "max"},
	}
	if err := s.db.Create(&users).Error; err != nil {
		return err
	}

	secrets := []Secret{
		{UserID: 1, Title: "Admin API Key", Value: "sk-admin-4f8a9c2e1b"},
		{UserID: 1, Title: "Database Password", Value: "super_secret_db_pass"},
		{UserID: 2, Title: "SSH Key", Value: "ssh-rsa AAAAB3NzaC1yc2EAAAA..."},
		{UserID: 2, Title: "Bank PIN", Value: "1234"},
		{UserID: 3, Title: "WiFi Password", Value: "p@ssw0rd123"},
		{UserID: 4, Title: "Bitcoin Wallet Key", Value: "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"},
	}
	if err := s.db.Create(&secrets).Error; err != nil {
		return err
	}

	comments := []Comment{
		{Username: "admin", Body: "Welcome to the DVGA guestbook!", CreatedAt: time.Now()},
		{Username: "gordonb", Body: "This is a test comment.", CreatedAt: time.Now()},
	}
	if err := s.db.Create(&comments).Error; err != nil {
		return err
	}

	return nil
}

// Reset drops all data and re-seeds.
func (s *Store) Reset() error {
	s.db.Exec("DELETE FROM reset_tokens")
	s.db.Exec("DELETE FROM comments")
	s.db.Exec("DELETE FROM secrets")
	s.db.Exec("DELETE FROM users")
	// Reset auto-increment counters
	s.db.Exec("DELETE FROM sqlite_sequence")
	return s.Seed()
}
