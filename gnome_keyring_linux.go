package keyring

/*
#cgo pkg-config: gnome-keyring-1 glib-2.0
#include <stdio.h>
#include <stdlib.h>
#include "gnome-keyring.h"

GnomeKeyringPasswordSchema keyring_schema =
  { GNOME_KEYRING_ITEM_GENERIC_SECRET,
    { { "username", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
      { "service",  GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
      { NULL,      0 } } };

GnomeKeyringResult gkr_set_password(gchar *description, gchar *service, gchar *username, gchar *password) {
	return gnome_keyring_store_password_sync(
		&keyring_schema,
		NULL,
		description,
		password,
		"service", service,
		"username", username,
		NULL);
}

GnomeKeyringResult gkr_get_password(gchar *service, gchar *username, gchar **password) {
	return gnome_keyring_find_password_sync(
		&keyring_schema,
		password,
		"service", service,
		"username", username,
		NULL);
}

*/
import "C"

import "unsafe"
import "fmt"

var (
	ErrDaemonCommunicationError = fmt.Errorf("Error communicating with the gnome-keyring daemon")
)

var gk_errors = map[int]error{
	6: ErrDaemonCommunicationError,
}

type gnomeKeyring struct{}

func (p gnomeKeyring) Set(Service, Username, Password string) error {
	desc := (*C.gchar)(C.CString("Username and password for " + Service))
	username := (*C.gchar)(C.CString(Username))
	service := (*C.gchar)(C.CString(Service))
	password := (*C.gchar)(C.CString(Password))
	defer C.free(unsafe.Pointer(desc))
	defer C.free(unsafe.Pointer(username))
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(password))

	result := C.gkr_set_password(desc,
		service,
		username,
		password)
	if result != C.GNOME_KEYRING_RESULT_OK {
		if knownErr, ok := gk_errors[int(result)]; ok {
			return knownErr
		}
		return fmt.Errorf("Unknown gnome-keyring error: %d", int(result))
	}
	return nil
}

func (p gnomeKeyring) Get(Service string, Username string) (string, error) {

	username := (*C.gchar)(C.CString(Username))
	service := (*C.gchar)(C.CString(Service))
	defer C.free(unsafe.Pointer(username))
	defer C.free(unsafe.Pointer(service))

	var pw *C.char
	pw = (*C.char)(C.malloc(C.size_t(300) * C.size_t(unsafe.Sizeof(pw))))
	defer C.free(unsafe.Pointer(pw))

	pwg := (*C.gchar)(pw)

	result := C.gkr_get_password(service,
		username,
		&pwg)
	if result != C.GNOME_KEYRING_RESULT_OK {
		if knownErr, ok := gk_errors[int(result)]; ok {
			return "", knownErr
		}
		return "", fmt.Errorf("Unknown gnome-keyring error: %d", int(result))
	}
	fmt.Println("result:", result, pw, C.GNOME_KEYRING_RESULT_OK)
	return C.GoString(pw), nil
}

func init() {
	RegisterProvider("gnome-keyring", gnomeKeyring{}, true)
}
