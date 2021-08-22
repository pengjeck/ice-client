package main

import (
	"context"
	"fmt"
	"github.com/pion/ice/v2"
	"github.com/pion/randutil"
	"net/http"
	"net/url"
	"time"
)

var (
	iceAgent          *ice.Agent
	remoteAuthChannel chan string
	remoteHost        string
	remoteHTTPPort    int
	localHTTPPort     int
)

func remoteAuth(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		panic(err)
	}

	remoteAuthChannel <- r.PostForm["ufrag"][0]
	remoteAuthChannel <- r.PostForm["pwd"][0]
}

// HTTP Listener to get ICE Candidate from remote Peer
func remoteCandidate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		panic(err)
	}

	c, err := ice.UnmarshalCandidate(r.PostForm["candidate"][0])
	if err != nil {
		panic(err)
	}
	fmt.Printf("candidate=%s\n", r.PostForm["candidate"])
	if err := iceAgent.AddRemoteCandidate(c); err != nil {
		panic(err)
	}
}

func RunHTTPServer() {
	http.HandleFunc("/remoteAuth", remoteAuth)
	http.HandleFunc("/remoteCandidate", remoteCandidate)
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", localHTTPPort), nil)
		if err != nil {
			panic(err)
		}
	}()
}

func main() {
	remoteAuthChannel = make(chan string, 3)

	RunHTTPServer()

	iceAgent, err := ice.NewAgent(&ice.AgentConfig{
		NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4},
	})
	if err != nil {
		panic(err)
	}

	// When we have gathered a new ICE Candidate send it to the remote peer
	if err = iceAgent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			return
		}

		_, err = http.PostForm(fmt.Sprintf("http://%s:%d/remoteCandidate", remoteHost, remoteHTTPPort), //nolint
			url.Values{
				"candidate": {c.Marshal()},
			})
		if err != nil {
			panic(err)
		}
	}); err != nil {
		panic(err)
	}

	// When ICE Connection state has change print to stdout
	if err = iceAgent.OnConnectionStateChange(func(c ice.ConnectionState) {
		fmt.Printf("ICE Connection State has changed: %s\n", c.String())
	}); err != nil {
		panic(err)
	}

	localUfrag, localPwd, err := iceAgent.GetLocalUserCredentials()
	if err != nil {
		panic(err)
	}

	urlStr := fmt.Sprintf("http://%s:%d/remoteAuth", remoteHost, remoteHTTPPort)
	_, err = http.PostForm(urlStr, url.Values{
		"ufrag": {localUfrag},
		"pwd":   {localPwd},
	})
	if err != nil {
		panic(err)
	}

	if err = iceAgent.GatherCandidates(); err != nil {
		panic(err)
	}
	fmt.Printf("Gather candidate finished.")

	remoteUfrag := <-remoteAuthChannel
	remotePwd := <-remoteAuthChannel

	conn, err := iceAgent.Accept(context.TODO(), remoteUfrag, remotePwd)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			time.Sleep(time.Second * 3)

			val, err := randutil.GenerateCryptoRandomString(15,
				"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
			if err != nil {
				panic(err)
			}
			if _, err = conn.Write([]byte(val)); err != nil {
				panic(err)
			}

			fmt.Printf("Sent: '%s'\n", val)
		}
	}()

	// Receive messages in a loop from the remote peer
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Received: '%s'\n", string(buf[:n]))
	}
}
