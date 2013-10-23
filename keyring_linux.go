// +build linux

package keyring

import (
	"fmt"
	dbus "github.com/guelfey/go.dbus"
)

const (
	ss_ServiceName    = "org.freedesktop.secrets"
	ss_ServicePath    = "/org/freedesktop/secrets"
	ss_CollectionPath = "/org/freedesktop/secrets/collection/default"

	ss_ServiceIface    = "org.freedesktop.Secret.Service."
	ss_SessionIface    = "org.freedesktop.Secret.Session."
	ss_CollectionIface = "org.freedesktop.Secret.Collection."
	ss_ItemIface       = "org.freedesktop.Secret.Item."
	ss_PromptIface     = "org.freedesktop.Secret.Prompt."
)

// The .Item interface speaks these. Note: Order is important
type ss_Secret struct {
	Session      dbus.ObjectPath
	Parameters   []byte
	Value        []byte
	Content_type string
}

// We'll always use text/plain, may need tweaking if implementing encryption
// other than "plain"
func new_ss_Secret(session dbus.ObjectPath, secret string) (s ss_Secret) {
	s = ss_Secret{
		Content_type: "text/plain; charset=utf8",
		Parameters:   []byte(""),
		Session:      session,
		Value:        []byte(secret),
	}
	return
}

// Currently hard-coded to use the 'default' keychain
type SsProvider struct {
	*dbus.Conn
	srv *dbus.Object
}

// This is used to open a seassion for every get/set. Alternative might be to
// defer() the call to close when constructing the SsProvider
func (s *SsProvider) openSession() (*dbus.Object, error) {
	var disregard dbus.Variant
	var sessionPath dbus.ObjectPath
	path := fmt.Sprint(ss_ServiceIface, "OpenSession")
	err := s.srv.Call(path, 0, "plain", dbus.MakeVariant("")).Store(&disregard, &sessionPath)
	if err != nil {
		return nil, err
	}
	return s.Object(ss_ServiceName, sessionPath), nil
}

// Unsure how the .Prompt call surfaces, it hasn't come up.
func (s *SsProvider) unlock(p dbus.ObjectPath) error {
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	err := s.srv.Call(fmt.Sprint(ss_ServiceIface, "Unlock"), 0, []dbus.ObjectPath{p}).Store(&unlocked, &prompt)
	if err != nil {
		return err
	}
	if prompt != dbus.ObjectPath("/") {
		s.Object(ss_ServiceName, prompt).Call(fmt.Sprint(ss_PromptIface, "Prompt"), 0, "unlock")
	}
	return nil
}

func (s *SsProvider) Get(c, u string) (string, error) {
	var unlocked, locked []dbus.ObjectPath
	var secret ss_Secret
	search := map[string]string{
		"username": u,
		"service":  c,
	}

	session, err := s.openSession()
	if err != nil {
		return "", err
	}
	s.unlock(ss_CollectionPath)
	collection := s.Object(ss_ServiceName, ss_CollectionPath)

	collection.Call(fmt.Sprint(ss_CollectionIface, "SearchItems"), 0, search).Store(&unlocked, &locked)
	// results is a slice. Just grab the first one.
	if len(unlocked) == 0 && len(locked) == 0 {
		return "", ErrNotFound
	}
	if len(unlocked) == 0 {
		for _, r := range locked {
			s.unlock(r)
			s.Object(ss_ServiceName, r).Call(fmt.Sprint(ss_ItemIface, "GetSecret"), 0, session.Path()).Store(&secret)
			break
		}
	} else {
		for _, r := range unlocked {
			s.Object(ss_ServiceName, r).Call(fmt.Sprint(ss_ItemIface, "GetSecret"), 0, session.Path()).Store(&secret)
			break
		}
	}

	session.Call(fmt.Sprint(ss_SessionIface, "Close"), 0)
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
	s.unlock(ss_CollectionPath)
	collection := s.Object(ss_ServiceName, ss_CollectionPath)

	secret := new_ss_Secret(session.Path(), p)
	// the bool is "replace"
	collection.Call(fmt.Sprint(ss_CollectionIface, "CreateItem"), 0, properties, secret, true).Store(&item, &prompt)
	if prompt != "/" {
		s.Object(ss_ServiceName, prompt).Call(fmt.Sprint(ss_PromptIface, "Prompt"), 0, "unlock")
	}
	session.Call(fmt.Sprint(ss_SessionIface, "Close"), 0)
	return nil
}

func init() {
	conn, err := dbus.SessionBus()
	if err != nil {
		fmt.Println("Error connecting to bus, bailing")
		return
	}
	srv := conn.Object(ss_ServiceName, ss_ServicePath)
	p := &SsProvider{conn, srv}

	// Everything should implement dbus peer, so ping to make sure we have an object...
	_, err = p.openSession()
	if err != nil {
		fmt.Printf("Unable to open session%s%s: %s\n", conn, srv, err)
		return
	}

	defaultProvider = p
}
