// +build !gnome_keyring

package keyring

import (
	"fmt"
	dbus "github.com/guelfey/go.dbus"
)

const (
	ssServiceName    = "org.freedesktop.secrets"
	ssServicePath    = "/org/freedesktop/secrets"
	ssCollectionPath = "/org/freedesktop/secrets/collection/default"
	ssServiceIface    = "org.freedesktop.Secret.Service."
	ssSessionIface    = "org.freedesktop.Secret.Session."
	ssCollectionIface = "org.freedesktop.Secret.Collection."
	ssItemIface       = "org.freedesktop.Secret.Item."
	ssPromptIface     = "org.freedesktop.Secret.Prompt."
)

// ssSecret corresponds to org.freedesktop.Secret.Item
// Note: Order is important
type ssSecret struct {
	Session      dbus.ObjectPath
	Parameters   []byte
	Value        []byte
	ContentType string `dbus:"Content_type"`
}

// newSSSecret prepares an ssSecret for use
// Uses text/plain as the Content-type which may need to change in the future
func newSSSecret(session dbus.ObjectPath, secret string) (s ssSecret) {
	s = ssSecret{
		ContentType: "text/plain; charset=utf8",
		Parameters:   []byte{},
		Session:      session,
		Value:        []byte(secret),
	}
	return
}

// SsProvider implements the provider interface freedesktop SecretService
type SsProvider struct {
	*dbus.Conn
	srv *dbus.Object
}

// This is used to open a seassion for every get/set. Alternative might be to
// defer() the call to close when constructing the SsProvider
func (s *SsProvider) openSession() (*dbus.Object, error) {
	var disregard dbus.Variant
	var sessionPath dbus.ObjectPath
	path := fmt.Sprint(ssServiceIface, "OpenSession")
	err := s.srv.Call(path, 0, "plain", dbus.MakeVariant("")).Store(&disregard, &sessionPath)
	if err != nil {
		return nil, err
	}
	return s.Object(ssServiceName, sessionPath), nil
}

// Unsure how the .Prompt call surfaces, it hasn't come up.
func (s *SsProvider) unlock(p dbus.ObjectPath) error {
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	err := s.srv.Call(fmt.Sprint(ssServiceIface, "Unlock"), 0, []dbus.ObjectPath{p}).Store(&unlocked, &prompt)
	if err != nil {
		return err
	}
	if prompt != dbus.ObjectPath("/") {
		s.Object(ssServiceName, prompt).Call(fmt.Sprint(ssPromptIface, "Prompt"), 0, "unlock")
	}
	return nil
}

func (s *SsProvider) Get(c, u string) (string, error) {
	var unlocked, locked []dbus.ObjectPath
	var secret ssSecret
	search := map[string]string{
		"username": u,
		"service":  c,
	}

	session, err := s.openSession()
	if err != nil {
		return "", err
	}
	s.unlock(ssCollectionPath)
	collection := s.Object(ssServiceName, ssCollectionPath)

	collection.Call(fmt.Sprint(ssCollectionIface, "SearchItems"), 0, search).Store(&unlocked, &locked)
	// results is a slice. Just grab the first one.
	if len(unlocked) == 0 && len(locked) == 0 {
		return "", ErrNotFound
	}
	if len(unlocked) == 0 {
		for _, r := range locked {
			s.unlock(r)
			s.Object(ssServiceName, r).Call(fmt.Sprint(ssItemIface, "GetSecret"), 0, session.Path()).Store(&secret)
			break
		}
	} else {
		for _, r := range unlocked {
			s.Object(ssServiceName, r).Call(fmt.Sprint(ssItemIface, "GetSecret"), 0, session.Path()).Store(&secret)
			break
		}
	}

	session.Call(fmt.Sprint(ssSessionIface, "Close"), 0)
	return string(secret.Value), nil
}

func (s *SsProvider) Set(c, u, p string) error {
	var item, prompt dbus.ObjectPath
	properties := map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label": dbus.MakeVariant(fmt.Sprintf("%s - %s", u, c)),
		"org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(map[string]string{
			"username": u,
			"service":  c,
		}),
	}

	session, err := s.openSession()
	if err != nil {
		return err
	}
	s.unlock(ssCollectionPath)
	collection := s.Object(ssServiceName, ssCollectionPath)

	secret := newSSSecret(session.Path(), p)
	// the bool is "replace"
	collection.Call(fmt.Sprint(ssCollectionIface, "CreateItem"), 0, properties, secret, true).Store(&item, &prompt)
	if prompt != "/" {
		s.Object(ssServiceName, prompt).Call(fmt.Sprint(ssPromptIface, "Prompt"), 0, "unlock")
	}
	session.Call(fmt.Sprint(ssSessionIface, "Close"), 0)
	return nil
}

func init() {
	conn, err := dbus.SessionBus()
	if err != nil {
		fmt.Println("keyring/dbus: Error connecting to dbus session, not registering SecretService provider")
		return
	}
	srv := conn.Object(ssServiceName, ssServicePath)
	p := &SsProvider{conn, srv}

	// Everything should implement dbus peer, so ping to make sure we have an object...
	_, err = p.openSession()
	if err != nil {
		fmt.Printf("Unable to open session%s%s: %s\n", conn, srv, err)
		return
	}

	defaultProvider = p
}
