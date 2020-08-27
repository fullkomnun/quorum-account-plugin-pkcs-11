package testutil

import "os"

const (
	SLOT_LABEL = "SLOT_LABEL"
	SLOT_PIN   = "SLOT_PIN"
)

func SetSlotLabel(s string) {
	os.Setenv(SLOT_LABEL, s)
}

func SetSlotPIN(s string) {
	os.Setenv(SLOT_PIN, s)
}

func UnsetAll() {
	os.Unsetenv(SLOT_LABEL)
	os.Unsetenv(SLOT_PIN)
}
