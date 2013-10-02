// +build linux,!gnome-keyring

/*
This is largely pieced together from the draft API spec:
http://standards.freedesktop.org/secret-service/index.html
and from the python-secretservice bindings:
http://bazaar.launchpad.net/~mitya57/python-secretstorage/secretstorage-ng


The dbus binding used was light on examples, I have no clue if this is
"correct" use of the library.

This passes tests, which is good.
*/
package keyring

import (
	"fmt"
	"launchpad.net/~jamesh/go-dbus/trunk"
	"os"
)

// One could probably write a code generator to make go objects/methods from dbus specs.
const (
	defaultCollectionPath = "/org/freedesktop/secrets/aliases/default"
	secrets               = "org.freedesktop.secrets"
	service               = "org.freedesktop.Secret.Service"
	item                  = "org.freedesktop.Secret.Item"
	collection            = "org.freedesktop.Secret.Collection"
	prompt                = "org.freedesktop.Secret.Prompt"
)

// Secrets
type dbusSecret struct {
	Session      dbus.ObjectPath
	Parameters   []byte
	Value        []byte
	Content_type string
}

type dbusProvider struct {
	conn       *dbus.Connection
	collection *dbus.ObjectProxy
	session    dbus.ObjectPath
}

func (p *dbusProvider) newSecret(secret string) (s dbusSecret) {
	s.Session = p.session
	s.Content_type = "text/plain"
	s.Value = []byte(secret)
	return
}
func (p *dbusProvider) Get(Service, Username string) (string, error) {
	var resp []dbus.ObjectPath
	var err error
	prop := map[string]string{
		"username": Username,
		"service":  Service,
	}
	msg, err := p.collection.Call(collection, "SearchItems", prop)
	if err != nil {
		return "", err
	}
	if err = msg.Args(&resp); err != nil {
		return "", err
	}
	for _, path := range resp {
		var x string
		msg, err := p.conn.Object(secrets, path).Call(item, "GetSecret", p.session)
		if err != nil {
			return "", err
		}
		msg.Args(&x)
		return x, nil
	}
	return "", fmt.Errorf("unable to return any secrets")
}

func (p *dbusProvider) Set(Service, Username, Password string) error {
	var item, needPrompt dbus.ObjectPath
	var err error
	prop := map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label": dbus.Variant{fmt.Sprintf("%s - %s", Username, Service)},
		"org.freedesktop.Secret.Item.Attributes": dbus.Variant{
			map[string]string{
				"username": Username,
				"service":  Service,
			},
		},
	}
	msg, err := p.collection.Call(collection, "CreateItem", prop, p.newSecret(Password), true)
	if err != nil {
		return err
	}
	err = msg.Args(&item, &needPrompt)
	if err != nil {
		return err
	}
	if string(item) == "/" {
		_, err := p.conn.Object(secrets, needPrompt).Call(prompt, "Prompt", "secret")
		if err != nil {
			return err
		}
		return p.Set(Service, Username, Password)
	}
	return nil
}

func init() {
	conn, err := dbus.Connect(dbus.SessionBus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(-1)
	}
	var discard dbus.Variant
	var session dbus.ObjectPath
	obj := conn.Object(secrets, "/org/freedesktop/secrets")
	msg, err := obj.Call(service, "OpenSession", "plain", dbus.Variant{""})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(-2)
	}
	err = msg.Args(&discard, &session)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(-3)
	}
	col := conn.Object(secrets, defaultCollectionPath)
	defaultProvider = &dbusProvider{conn, col, session}
}
