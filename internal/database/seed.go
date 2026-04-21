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
		{ID: 1, Username: "admin", Password: "admin", Role: "admin",
			Email: "admin@corp.local", Phone: "555-0100",
			SecretQuestion: "What is your favourite colour?", SecretAnswer: "red"},
		{ID: 2, Username: "gordonb", Password: "abc123", Role: "user",
			Email: "gordon@corp.local", Phone: "555-0101",
			SecretQuestion: "What is your favourite colour?", SecretAnswer: "blue"},
		{ID: 3, Username: "pablo", Password: "letmein", Role: "user",
			Email: "pablo@corp.local", Phone: "555-0102",
			SecretQuestion: "What is your pet's name?", SecretAnswer: "buddy"},
		{ID: 4, Username: "1337", Password: "charley", Role: "user",
			Email: "leet@corp.local", Phone: "555-0103",
			SecretQuestion: "What is your pet's name?", SecretAnswer: "max"},
		{ID: 5, Username: "helpdesk", Password: "help1234", Role: "helpdesk",
			Email: "helpdesk@corp.local", Phone: "555-0199",
			SecretQuestion: "What is your department?", SecretAnswer: "support"},
		{ID: 6, Username: "support", Password: "support1", Role: "support",
			Email: "support@corp.local", Phone: "555-0198",
			SecretQuestion: "What is your department?", SecretAnswer: "support"},
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

	now := time.Now()
	orders := []Order{
		{ID: 1, UserID: 2, Product: "Laptop Pro 15", Amount: 1299.99, Status: "shipped",
			TrackingNumber: "TRK-001-XYZ", CardLast4: "4242", CVV: "123", AssignedTo: 5, CreatedAt: now.Add(-72 * time.Hour)},
		{ID: 2, UserID: 2, Product: "Mechanical Keyboard", Amount: 149.50, Status: "pending",
			TrackingNumber: "", CardLast4: "4242", CVV: "123", AssignedTo: 5, CreatedAt: now.Add(-24 * time.Hour)},
		{ID: 3, UserID: 3, Product: "USB-C Hub", Amount: 49.99, Status: "shipped",
			TrackingNumber: "TRK-002-ABC", CardLast4: "1234", CVV: "456", AssignedTo: 5, CreatedAt: now.Add(-48 * time.Hour)},
		{ID: 4, UserID: 3, Product: "Monitor Stand", Amount: 79.00, Status: "cancelled",
			TrackingNumber: "", CardLast4: "1234", CVV: "456", AssignedTo: 0, CreatedAt: now.Add(-96 * time.Hour)},
		{ID: 5, UserID: 4, Product: "Noise Cancelling Headphones", Amount: 299.00, Status: "shipped",
			TrackingNumber: "TRK-003-DEF", CardLast4: "9999", CVV: "789", AssignedTo: 5, CreatedAt: now.Add(-12 * time.Hour)},
		{ID: 6, UserID: 1, Product: "Server Rack Unit", Amount: 4500.00, Status: "pending",
			TrackingNumber: "", CardLast4: "0001", CVV: "321", AssignedTo: 0, CreatedAt: now.Add(-1 * time.Hour)},
	}
	if err := s.db.Create(&orders).Error; err != nil {
		return err
	}

	documents := []Document{
		{ID: 1, OwnerUserID: 1, Title: "Q4 Budget Report", Body: "Total budget: $2.4M. R&D: $800K. Marketing: $400K.", Classification: "confidential"},
		{ID: 2, OwnerUserID: 1, Title: "Infrastructure Overview", Body: "Primary DC: us-east-1. Backup: eu-west-1. VPN subnet: 10.0.0.0/8.", Classification: "internal"},
		{ID: 3, OwnerUserID: 2, Title: "Onboarding Guide", Body: "Welcome to the team! First steps: set up VPN, request system access.", Classification: "internal"},
		{ID: 4, OwnerUserID: 2, Title: "Personal Notes", Body: "Project Phoenix deadline: March 15. Budget approved by Sarah.", Classification: "confidential"},
		{ID: 5, OwnerUserID: 3, Title: "Team Handbook", Body: "PTO policy: 20 days/year. Remote work: Tues/Thurs.", Classification: "public"},
		{ID: 6, OwnerUserID: 4, Title: "Security Audit Notes", Body: "Critical findings: outdated TLS 1.0, admin panel exposed on 8080.", Classification: "confidential"},
	}
	if err := s.db.Create(&documents).Error; err != nil {
		return err
	}

	invoices := []Invoice{
		{ID: 1, UserID: 2, OrderID: 1, Amount: 1299.99, Status: "paid", Notes: "Standard purchase"},
		{ID: 2, UserID: 2, OrderID: 2, Amount: 149.50, Status: "open", Notes: ""},
		{ID: 3, UserID: 3, OrderID: 3, Amount: 49.99, Status: "paid", Notes: "Expedited shipping"},
		{ID: 4, UserID: 3, OrderID: 4, Amount: 79.00, Status: "voided", Notes: "Customer cancelled"},
		{ID: 5, UserID: 4, OrderID: 5, Amount: 299.00, Status: "open", Notes: ""},
	}
	if err := s.db.Create(&invoices).Error; err != nil {
		return err
	}

	notifications := []Notification{
		{SenderID: 1, Recipient: "all@corp.local", Body: "System maintenance scheduled for Sunday 2AM–4AM UTC.", CreatedAt: now.Add(-48 * time.Hour)},
		{SenderID: 1, Recipient: "gordonb@corp.local", Body: "Your order #1 has shipped.", CreatedAt: now.Add(-72 * time.Hour)},
		{SenderID: 5, Recipient: "pablo@corp.local", Body: "Your support ticket has been updated.", CreatedAt: now.Add(-24 * time.Hour)},
	}
	if err := s.db.Create(&notifications).Error; err != nil {
		return err
	}

	return nil
}

// Reset drops all data and re-seeds.
func (s *Store) Reset() error {
	for _, tbl := range []string{
		"notifications", "api_tokens", "invoices", "documents", "orders",
		"reset_tokens", "comments", "secrets", "users",
	} {
		s.db.Exec("DELETE FROM " + tbl)
	}
	s.db.Exec("DELETE FROM sqlite_sequence")
	return s.Seed()
}

