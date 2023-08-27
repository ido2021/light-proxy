package light_proxy

import (
	"encoding/json"
	"errors"
	"github.com/ido2021/light-proxy/adaptor/inbound"
	"github.com/ido2021/light-proxy/adaptor/outbound"
	"github.com/ido2021/light-proxy/common"
	"github.com/ido2021/light-proxy/route"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 & http protocol
type Server struct {
	config          *common.Config
	inboundAdaptors []inbound.InAdaptor
	running         bool
	closed          chan struct{}
	router          *route.Router
}

// New creates a new Server and potentially returns an error
func New(confPath string) (*Server, error) {
	data, err := os.ReadFile(confPath)
	if err != nil {
		return nil, err
	}
	config := &common.Config{}
	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	var adaptors []inbound.InAdaptor
	for _, l := range config.Inbounds {
		factory := inbound.GetInAdaptorFactory(inbound.Protocol(l.Type))
		if factory == nil {
			return nil, errors.New("不支持的协议: " + l.Type)
		}
		adaptor, err := factory(l.Config)
		if err != nil {
			return nil, err
		}
		adaptors = append(adaptors, adaptor)
	}

	// 默认接出
	outAdaptors := map[string]outbound.OutAdaptor{
		outbound.Direct: NewDNSCacheOutAdaptor(&outbound.DirectOutAdaptor{}),
		outbound.Block:  &outbound.BlockOutAdaptor{},
	}

	factory := outbound.GetOutAdaptorFactory(config.Outbound.Type)
	if factory != nil {
		outAdaptor, err := factory(config.Outbound.Config)
		if err != nil {
			return nil, err
		}
		outAdaptors[outbound.Proxy] = NewDNSCacheOutAdaptor(outAdaptor)
	}

	router, err := route.NewRouter(config.Route, outAdaptors)
	if err != nil {
		return nil, err
	}
	server := &Server{
		config:          config,
		inboundAdaptors: adaptors,
		router:          router,
		closed:          make(chan struct{}),
	}

	return server, nil
}

// Start is used to create a listener and serve on it
func (s *Server) Start() error {
	if s.running {
		return nil
	}
	for _, adaptor := range s.inboundAdaptors {
		go func() {
			err := adaptor.Start(s.router)
			log.Println(err)
		}()
	}
	s.waitOnExit()
	return nil
}

func (s *Server) waitOnExit() {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	select {
	case sig := <-signals:
		log.Printf("Got %s signal. Aborting...\n", sig)
		_ = s.Stop()
	case <-s.closed:
		// 不再监听信号
		signal.Stop(signals)
	}
}

func (s *Server) Stop() error {
	if s.running {
		s.running = false
		s.closed <- struct{}{}
		for _, adaptor := range s.inboundAdaptors {
			err := adaptor.Stop()
			if err != nil {
				log.Println(err)
			}
		}
	}
	return nil
}
