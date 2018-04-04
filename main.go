package main

import (
	"fmt"
	"os"

	"github.com/superfly/burn/cmd"
)

func main() {
	// if err := agent.Listen(agent.Options{}); err != nil {
	// 	log.Fatal(err)
	// }
	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
