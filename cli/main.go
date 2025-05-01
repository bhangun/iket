package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "hello-client",
		Usage: "Client for the hello-world server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "server",
				Value: "http://localhost:8080",
				Usage: "Server address",
			},
		},
		Action: func(c *cli.Context) error {
			server := c.String("server")
			client := &http.Client{Timeout: 5 * time.Second}

			resp, err := client.Get(server)
			if err != nil {
				return fmt.Errorf("request failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("unexpected status: %s", resp.Status)
			}

			buf := make([]byte, 1024)
			n, _ := resp.Body.Read(buf)
			fmt.Println(string(buf[:n]))
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
