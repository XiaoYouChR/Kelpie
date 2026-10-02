package nat

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

const igdV1Description = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <friendlyName>Fake Router</friendlyName>
  <deviceList>
   <device>
    <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
    <deviceList>
     <device>
      <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
      <serviceList>
       <service>
        <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>
        <controlURL>/ctl/CmnIfCfg</controlURL>
       </service>
       <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
        <controlURL>/ctl/IPConn</controlURL>
       </service>
      </serviceList>
     </device>
    </deviceList>
   </device>
  </deviceList>
 </device>
</root>`

const igdV2Description = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType>
  <deviceList>
   <device>
    <deviceType>urn:schemas-upnp-org:device:WANDevice:2</deviceType>
    <deviceList>
     <device>
      <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:2</deviceType>
      <serviceList>
       <service>
        <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:2</serviceType>
        <controlURL>http://10.255.255.1:5000/ctl/PPPConn</controlURL>
       </service>
      </serviceList>
     </device>
    </deviceList>
   </device>
  </deviceList>
 </device>
</root>`

// mixedDescription is an IGD:2 gateway whose WANDevice and WANIPConnection
// say version 1, as some routers have them.
const mixedDescription = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType>
  <deviceList>
   <device>
    <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
    <deviceList>
     <device>
      <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:2</deviceType>
      <serviceList>
       <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnectionFoo:1</serviceType>
        <controlURL>/ctl/Foo</controlURL>
       </service>
       <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <controlURL>/ctl/IPConn</controlURL>
       </service>
      </serviceList>
     </device>
    </deviceList>
   </device>
  </deviceList>
 </device>
</root>`

const notGatewayDescription = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <device><deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType></device>
</root>`

type soapCall struct {
	action, urn, protocol, internalClient, description string
	port, internalPort, lease                          int
}

type fakeGateway struct {
	t           *testing.T
	server      *httptest.Server
	description string
	controlPath string
	externalIP  string
	failures    map[string]int

	mu    sync.Mutex
	calls []soapCall
}

func newFakeGateway(t *testing.T, description, controlPath string) *fakeGateway {
	g := &fakeGateway{t: t, description: description, controlPath: controlPath, externalIP: "203.0.113.7", failures: map[string]int{}}
	g.server = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.server.Close)
	return g
}

func (g *fakeGateway) location() string {
	return g.server.URL + "/rootDesc.xml"
}

func (g *fakeGateway) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/rootDesc.xml":
		io.WriteString(w, g.description)
	case r.Method == http.MethodPost && r.URL.Path == g.controlPath:
		g.serveSOAP(w, r)
	default:
		http.NotFound(w, r)
	}
}

var soapActionPattern = regexp.MustCompile(`^"(.+)#(\w+)"$`)

func (g *fakeGateway) serveSOAP(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("SOAPAction")
	match := soapActionPattern.FindStringSubmatch(header)
	if match == nil {
		g.t.Errorf("malformed SOAPAction %q", header)
		http.Error(w, "bad SOAPAction", http.StatusBadRequest)
		return
	}
	var envelope struct {
		Body struct {
			Inner struct {
				XMLName        xml.Name
				ExternalPort   int    `xml:"NewExternalPort"`
				Protocol       string `xml:"NewProtocol"`
				InternalPort   int    `xml:"NewInternalPort"`
				InternalClient string `xml:"NewInternalClient"`
				Description    string `xml:"NewPortMappingDescription"`
				Lease          int    `xml:"NewLeaseDuration"`
			} `xml:",any"`
		}
	}
	if err := xml.NewDecoder(r.Body).Decode(&envelope); err != nil {
		g.t.Errorf("decode SOAP body: %v", err)
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	inner := envelope.Body.Inner
	if inner.XMLName.Local != match[2] || inner.XMLName.Space != match[1] {
		g.t.Errorf("body element %v does not match SOAPAction %q", inner.XMLName, header)
	}
	call := soapCall{
		action: match[2], urn: match[1], protocol: inner.Protocol, internalClient: inner.InternalClient,
		description: inner.Description, port: inner.ExternalPort, internalPort: inner.InternalPort, lease: inner.Lease,
	}
	g.mu.Lock()
	g.calls = append(g.calls, call)
	g.mu.Unlock()

	if code, ok := g.failures[call.action+":"+call.protocol]; ok {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>
<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>
<detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>%d</errorCode><errorDescription>ConflictInMappingEntry</errorDescription></UPnPError></detail>
</s:Fault></s:Body></s:Envelope>`, code)
		return
	}
	fmt.Fprintf(w, `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:%sResponse xmlns:u="%s"><NewExternalIPAddress>%s</NewExternalIPAddress></u:%sResponse>
</s:Body></s:Envelope>`, call.action, call.urn, g.externalIP, call.action)
}

func (g *fakeGateway) actions() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var actions []string
	for _, c := range g.calls {
		switch c.action {
		case "AddPortMapping":
			actions = append(actions, fmt.Sprintf("add:%s:%d", c.protocol, c.port))
		case "DeletePortMapping":
			actions = append(actions, fmt.Sprintf("delete:%s:%d", c.protocol, c.port))
		}
	}
	return actions
}

func (g *fakeGateway) callsOf(action string) []soapCall {
	g.mu.Lock()
	defer g.mu.Unlock()
	var calls []soapCall
	for _, c := range g.calls {
		if c.action == action {
			calls = append(calls, c)
		}
	}
	return calls
}

func TestOpenMapsTCPAndUDPAndCloseDeletesThem(t *testing.T) {
	gateway := newFakeGateway(t, igdV1Description, "/ctl/IPConn")

	closeMappings, external, err := openAt(context.Background(), []string{gateway.location()}, buildMappings(4662, 4672), "Kelpie <eD2k> & Kad")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if want := netip.MustParseAddr("203.0.113.7"); external != want {
		t.Fatalf("external = %v, want %v", external, want)
	}
	if got, want := gateway.actions(), []string{"add:TCP:4662", "add:UDP:4672"}; !slices.Equal(got, want) {
		t.Fatalf("actions = %v, want %v", got, want)
	}
	for _, c := range gateway.callsOf("AddPortMapping") {
		if c.urn != "urn:schemas-upnp-org:service:WANIPConnection:1" {
			t.Errorf("urn = %q", c.urn)
		}
		if c.lease != 0 || c.internalPort != c.port || c.internalClient != "127.0.0.1" {
			t.Errorf("unexpected mapping %+v", c)
		}
		if c.description != "Kelpie <eD2k> & Kad" {
			t.Errorf("description = %q", c.description)
		}
	}

	if err := closeMappings(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	want := []string{"add:TCP:4662", "add:UDP:4672", "delete:TCP:4662", "delete:UDP:4672"}
	if got := gateway.actions(); !slices.Equal(got, want) {
		t.Fatalf("actions = %v, want %v", got, want)
	}
}

func TestOpenMapsOnEveryGateway(t *testing.T) {
	gatewayA := newFakeGateway(t, igdV1Description, "/ctl/IPConn")
	gatewayB := newFakeGateway(t, igdV1Description, "/ctl/IPConn")

	closeMappings, _, err := openAt(context.Background(), []string{gatewayA.location(), gatewayB.location()}, buildMappings(4661, 4662), "Kelpie")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := closeMappings(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	want := []string{"add:TCP:4661", "add:UDP:4662", "delete:TCP:4661", "delete:UDP:4662"}
	for name, gateway := range map[string]*fakeGateway{"A": gatewayA, "B": gatewayB} {
		if got := gateway.actions(); !slices.Equal(got, want) {
			t.Errorf("gateway %s actions = %v, want %v", name, got, want)
		}
	}
}

func TestOpenReturnsErrorWhenNoGatewayFound(t *testing.T) {
	if _, _, err := openAt(context.Background(), nil, buildMappings(4661, 4662), "Kelpie"); err == nil {
		t.Fatal("expected error")
	}
}

func TestOpenSkipsZeroPort(t *testing.T) {
	gateway := newFakeGateway(t, igdV1Description, "/ctl/IPConn")

	if _, _, err := openAt(context.Background(), []string{gateway.location()}, buildMappings(4661, 0), "Kelpie"); err != nil {
		t.Fatalf("open: %v", err)
	}
	if got, want := gateway.actions(), []string{"add:TCP:4661"}; !slices.Equal(got, want) {
		t.Fatalf("actions = %v, want %v", got, want)
	}
}

func TestOpenRejectsNoPorts(t *testing.T) {
	gateway := newFakeGateway(t, igdV1Description, "/ctl/IPConn")
	probeUPnP := func(context.Context) []string { return []string{gateway.location()} }

	if _, _, err := openWith(context.Background(), route{}, route{}, probeUPnP, 0, 0, "Kelpie", testTiming); err == nil {
		t.Fatal("expected error")
	}
	if got := gateway.actions(); len(got) != 0 {
		t.Fatalf("actions = %v, want none", got)
	}
}

func TestOpenKeepsPartialMapping(t *testing.T) {
	gateway := newFakeGateway(t, igdV1Description, "/ctl/IPConn")
	gateway.failures["AddPortMapping:UDP"] = 718

	closeMappings, _, err := openAt(context.Background(), []string{gateway.location()}, buildMappings(4661, 4662), "Kelpie")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := closeMappings(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got, want := gateway.actions(), []string{"add:TCP:4661", "add:UDP:4662", "delete:TCP:4661"}; !slices.Equal(got, want) {
		t.Fatalf("actions = %v, want %v", got, want)
	}
}

func TestOpenFailsWhenEveryMappingIsRefused(t *testing.T) {
	gateway := newFakeGateway(t, igdV1Description, "/ctl/IPConn")
	gateway.failures["AddPortMapping:TCP"] = 718
	gateway.failures["AddPortMapping:UDP"] = 718

	_, _, err := openAt(context.Background(), []string{gateway.location()}, buildMappings(4661, 4662), "Kelpie")
	if err == nil || !strings.Contains(err.Error(), "UPnP error 718") {
		t.Fatalf("err = %v, want UPnP error 718", err)
	}
}

func TestOpenWithoutExternalAddress(t *testing.T) {
	gateway := newFakeGateway(t, igdV1Description, "/ctl/IPConn")
	gateway.externalIP = ""

	_, external, err := openAt(context.Background(), []string{gateway.location()}, buildMappings(4661, 0), "Kelpie")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if external.IsValid() {
		t.Fatalf("external = %v, want zero Addr", external)
	}
}

func TestOpenSupportsIGDv2WithForeignHostInControlURL(t *testing.T) {
	gateway := newFakeGateway(t, igdV2Description, "/ctl/PPPConn")

	_, _, err := openAt(context.Background(), []string{gateway.location()}, buildMappings(4661, 0), "Kelpie")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	calls := gateway.callsOf("AddPortMapping")
	if len(calls) != 1 || calls[0].urn != "urn:schemas-upnp-org:service:WANPPPConnection:2" {
		t.Fatalf("calls = %+v", calls)
	}
}

// Routers mix IGD:1 and IGD:2 levels; each is matched whatever its version
// (aMule UPnPBase.cpp TypeMatchesIgnoringVersion).
func TestOpenSupportsMixedIGDVersions(t *testing.T) {
	gateway := newFakeGateway(t, mixedDescription, "/ctl/IPConn")

	_, _, err := openAt(context.Background(), []string{gateway.location()}, buildMappings(4661, 0), "Kelpie")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	calls := gateway.callsOf("AddPortMapping")
	if len(calls) != 1 || calls[0].urn != "urn:schemas-upnp-org:service:WANIPConnection:1" {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestOpenRejectsNonGatewayDevice(t *testing.T) {
	gateway := newFakeGateway(t, notGatewayDescription, "/ctl/IPConn")

	if _, _, err := openAt(context.Background(), []string{gateway.location()}, buildMappings(4661, 4662), "Kelpie"); err == nil {
		t.Fatal("expected error")
	}
}

func TestOpenStopsWhenContextIsCancelled(t *testing.T) {
	gateway := newFakeGateway(t, igdV1Description, "/ctl/IPConn")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, err := openAt(ctx, []string{gateway.location()}, buildMappings(4661, 4662), "Kelpie"); err == nil {
		t.Fatal("expected error")
	}
	if got := gateway.actions(); len(got) != 0 {
		t.Fatalf("actions = %v, want none", got)
	}
}

func TestParseSearchResponse(t *testing.T) {
	deviceType := "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
	response := func(st, location string) []byte {
		return []byte(strings.ReplaceAll(fmt.Sprintf("HTTP/1.1 200 OK\nCACHE-CONTROL: max-age=120\nST: %s\nUSN: uuid:abc::%s\nEXT:\nSERVER: Linux UPnP/1.1 MiniUPnPd/2.3\nLOCATION: %s\n\n", st, st, location), "\n", "\r\n"))
	}

	location, err := parseSearchResponse(deviceType, response(deviceType, "http://192.168.1.1:5000/rootDesc.xml"))
	if err != nil || location != "http://192.168.1.1:5000/rootDesc.xml" {
		t.Fatalf("location = %q, err = %v", location, err)
	}
	if _, err := parseSearchResponse(deviceType, response("urn:schemas-upnp-org:device:InternetGatewayDevice:2", "http://192.168.1.1/")); err == nil {
		t.Error("expected error for other device type")
	}
	if _, err := parseSearchResponse(deviceType, response(deviceType, "")); err == nil {
		t.Error("expected error for missing location")
	}
	if _, err := parseSearchResponse(deviceType, []byte("garbage")); err == nil {
		t.Error("expected error for garbage")
	}
}

func TestToControlURL(t *testing.T) {
	base, _ := url.Parse("http://192.168.1.1:5000/desc/rootDesc.xml")
	cases := map[string]string{
		"/ctl/IPConn":                    "http://192.168.1.1:5000/ctl/IPConn",
		"ctl/IPConn":                     "http://192.168.1.1:5000/desc/ctl/IPConn",
		"/ctl?service=WANIPConn":         "http://192.168.1.1:5000/ctl?service=WANIPConn",
		"http://10.0.0.1:80/ctl/IPConn":  "http://192.168.1.1:5000/ctl/IPConn",
		"http://10.0.0.1/upnp?x=1&y=two": "http://192.168.1.1:5000/upnp?x=1&y=two",
	}
	for controlURL, want := range cases {
		got, err := toControlURL(base, controlURL)
		if err != nil || got != want {
			t.Errorf("toControlURL(%q) = %q, %v; want %q", controlURL, got, err, want)
		}
	}
}

func TestMatchType(t *testing.T) {
	for urn, want := range map[string]bool{
		"urn:schemas-upnp-org:service:WANIPConnection:1":    true,
		"urn:schemas-upnp-org:service:WANIPConnection:2":    true,
		"URN:schemas-upnp-org:service:wanipconnection:1":    true,
		"urn:schemas-upnp-org:service:WANIPConnectionFoo:1": false,
		"urn:schemas-upnp-org:service:WANIPConnection:":     false,
		"urn:schemas-upnp-org:service:WANPPPConnection:1":   false,
	} {
		if got := matchType(urn, "service:WANIPConnection"); got != want {
			t.Errorf("matchType(%q) = %v", urn, got)
		}
	}
}
