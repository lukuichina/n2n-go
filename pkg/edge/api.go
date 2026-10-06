package edge

import (
	"embed"
	"fmt"
	"io/fs"
	"n2n-go/pkg/log"
	"n2n-go/pkg/p2p"
	"n2n-go/pkg/protocol/netstruct"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

//go:embed assets
var webAssets embed.FS

func getFileSystem() (http.FileSystem, error) {
	fsys, err := fs.Sub(webAssets, "assets")
	if err != nil {
		return nil, fmt.Errorf("cannot get embeded Filesystem")
	}

	return http.FS(fsys), nil
}

type EdgeClientApi struct {
	Api                     *echo.Echo
	Client                  *EdgeClient
	IsWaitingForLeasesInfos bool
	LastLeasesInfos         *netstruct.LeasesInfos
}

func (eapi *EdgeClientApi) GetPeersJSON(c echo.Context) error {
	err := eapi.Client.sendP2PFullStateRequest()
	if err != nil {
		return err
	}
	for {
		if eapi.Client.Peers.IsWaitingCommunityDatas {
			time.Sleep(300 * time.Millisecond)
		} else {
			break
		}
	}
	return c.JSON(http.StatusOK, eapi.Client.Peers.P2PCommunityDatas)
}

func (eapi *EdgeClientApi) GetLeasesInfosJSON(c echo.Context) error {
	err := eapi.sendLeasesInfosRequest()
	if err != nil {
		return err
	}
	for {
		if eapi.IsWaitingForLeasesInfos {
			time.Sleep(300 * time.Millisecond)
		} else {
			break
		}
	}
	return c.JSON(http.StatusOK, eapi.LastLeasesInfos)
}

func (eapi *EdgeClientApi) WaitForCommunityDatasUpdate(timeout time.Duration) {
	start := time.Now()
	for {
		if eapi.Client.Peers.IsWaitingCommunityDatas {
			time.Sleep(300 * time.Millisecond)
		} else {
			break
		}
		if time.Since(start) >= timeout {
			eapi.Client.Peers.IsWaitingCommunityDatas = false
		}
	}
}

func (eapi *EdgeClientApi) GetOfflinesDot(c echo.Context) error {
	eapi.WaitForCommunityDatasUpdate(3 * time.Second)
	return c.String(http.StatusOK, eapi.Client.Peers.GenOfflinesDot())
}

func (eapi *EdgeClientApi) GetPeersDot(c echo.Context) error {
	err := eapi.Client.sendP2PFullStateRequest()
	if err != nil {
		return err
	}
	eapi.WaitForCommunityDatasUpdate(3 * time.Second)
	return c.String(http.StatusOK, eapi.Client.Peers.GenPeersDot())
}

func (eapi *EdgeClientApi) GetPeersSVG(c echo.Context) error {
	err := eapi.Client.sendP2PFullStateRequest()
	if err != nil {
		return err
	}
	eapi.WaitForCommunityDatasUpdate(3 * time.Second)
	cp2p, err := p2p.NewCommunityP2PVizDatas(eapi.Client.Community, eapi.Client.Peers.Reachables)
	if err != nil {
		return err
	}
	res, err := cp2p.GenerateP2PGraphImage()
	if err != nil {
		return err
	}
	return c.Blob(http.StatusOK, "image/svg+xml", res)
}

func (eapi *EdgeClientApi) GetPeersHTML(c echo.Context) error {
	return c.HTML(http.StatusOK, eapi.Client.Peers.GenPeersHTML())
}

func (eapi *EdgeClientApi) GetHostsFile(c echo.Context) error {
	return c.String(http.StatusOK, eapi.Client.Hosts.String())
}

// GetSocks5JSON reports whether the ingress proxy is running and what it has
// been doing. It answers 404 when no --socks5-listen was given, so a scrape
// can tell "not enabled" apart from "enabled but idle".
func (eapi *EdgeClientApi) GetSocks5JSON(c echo.Context) error {
	if eapi.Client.Socks5 == nil {
		return c.JSON(http.StatusNotFound, map[string]any{"enabled": false})
	}
	st := eapi.Client.Socks5.Stats()
	return c.JSON(http.StatusOK, map[string]any{"enabled": true, "stats": st})
}

// GetPortForwardJSON reports the local and remote TCP port forwarders. It
// answers 404 when neither -L nor -R was given.
func (eapi *EdgeClientApi) GetPortForwardJSON(c echo.Context) error {
	if len(eapi.Client.Forwards) == 0 && len(eapi.Client.RemoteForwards) == 0 {
		return c.JSON(http.StatusNotFound, map[string]any{"enabled": false})
	}
	local := make([]PortForwardStats, 0, len(eapi.Client.Forwards))
	for _, pf := range eapi.Client.Forwards {
		local = append(local, pf.Stats())
	}
	remote := make([]PortForwardStats, 0, len(eapi.Client.RemoteForwards))
	for _, pf := range eapi.Client.RemoteForwards {
		remote = append(remote, pf.Stats())
	}
	return c.JSON(http.StatusOK, map[string]any{
		"enabled": true,
		"local":   local,
		"remote":  remote,
	})
}

func NewEdgeApi(edge *EdgeClient) *EdgeClientApi {
	api := echo.New()
	eapi := &EdgeClientApi{
		Api:    api,
		Client: edge,
	}
	eapi.Api.HideBanner = true
	eapi.Api.HidePort = true
	eapi.Api.Use(middleware.Recover())
	eapi.Api.Use(middleware.RemoveTrailingSlash())
	fs, err := getFileSystem()
	if err != nil {
		log.Fatalf(" unable to init edgeApi: %v", err)
	}
	assetHandler := http.FileServer(fs)
	eapi.Api.GET("/static/*", echo.WrapHandler(http.StripPrefix("/static/", assetHandler)))
	eapi.Api.GET("/peers", eapi.GetPeersHTML)
	eapi.Api.GET("/peers.json", eapi.GetPeersJSON)
	eapi.Api.GET("/peers.dot", eapi.GetPeersDot)
	eapi.Api.GET("/peers.svg", eapi.GetPeersSVG)
	eapi.Api.GET("/leases.json", eapi.GetLeasesInfosJSON)
	eapi.Api.GET("/offlines.dot", eapi.GetOfflinesDot)
	eapi.Api.GET("/syshosts/file", eapi.GetHostsFile)
	eapi.Api.GET("/socks5.json", eapi.GetSocks5JSON)
	eapi.Api.GET("/portforward.json", eapi.GetPortForwardJSON)
	return eapi
}

func (eapi *EdgeClientApi) Run() {
	log.Printf("started management api at %s", eapi.Client.config.APIListenAddr)
	eapi.Api.Logger.Fatal(eapi.Api.Start(eapi.Client.config.APIListenAddr))
}
